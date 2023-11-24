from datetime import datetime
import logging
from typing import Optional
from typing import Union
import requests

from cryptojwt import JWT
from cryptojwt.jws.jws import factory
from cryptojwt.jwt import utc_time_sans_frac
from fedservice.entity import get_federation_entity
from idpyoidc.exception import RequestError
from idpyoidc.message import Message
from idpyoidc.message import oidc
from idpyoidc.server.oidc.userinfo import UserInfo
from idpyoidc.server.util import execute
from idpyoidc.util import rndstr
from idpysdjwt.issuer import Issuer

from openid4v.message import CredentialDefinition
from openid4v.message import CredentialRequest
from openid4v.message import CredentialResponse
from openid4v.message import CredentialsSupported
from openid4v.message import Proof

logger = logging.getLogger(__name__)


def get_keyjar(unit):
    _fed = get_federation_entity(unit)
    if _fed:
        return _fed.keyjar
    else:
        return unit.upstream_get("attribute", "keyjar")


class CredentialConstructor(object):
    def __init__(self, upstream_get, **kwargs):
        print("\nCredentialConstructor Init")
        self.upstream_get = upstream_get

    def calculate_attribute_disclosure(self, info):
        print("\nCredentialConstructor calculate attribute")
        attribute_disclosure = self.upstream_get("context").claims.get_preference(
            "attribute_disclosure"
        )
        if attribute_disclosure:
            return {
                "": {k: v for k, v in info.items() if k in attribute_disclosure[""]}
            }
        else:
            return {}

    def calculate_array_disclosure(self, info):
        print("\nCredentialConstructor calculate array")
        array_disclosure = self.upstream_get("context").claims.get_preference(
            "array_disclosure"
        )
        _discl = {}
        if array_disclosure:
            for k in array_disclosure:
                if k in info and len(info[k]) > 1:
                    _discl[k] = info[k]

        return _discl

    def matching_credentials_supported(self, request):
        print("\nCredentialConstructor matching")
        _supported = self.upstream_get("context").claims.get_preference(
            "credentials_supported"
        )
        matching = []
        for cs in _supported:
            if cs["format"] != request["format"]:
                continue
            _cred_def_sup = cs["credential_definition"]
            _req_cred_def = request["credential_definition"]
            # The set of type values must match
            if set(_cred_def_sup["type"]) != set(_req_cred_def["type"]):
                continue
            matching.append(_cred_def_sup.get("credentialSubject", {}))
        return matching

    def __call__(self, user_id: str, request: Union[dict, Message]) -> str:
        # compare what this entity supports with what is requested
        print("\nCredentialConstructor call")
        _matching = self.matching_credentials_supported(request)

        if _matching == []:
            raise RequestError("unsupported_credential_type")

        _cntxt = self.upstream_get("context")
        _mngr = _cntxt.session_manager
        _session_info = _mngr.get_session_info_by_token(
            request["access_token"], grant=True, handler_key="access_token"
        )

        # This is what the requester hopes to get
        if "credential_definition" in request:
            _req_cd = CredentialDefinition().from_dict(request["credential_definition"])
            csub = _req_cd.get("credentialSubject", {})
            if csub:
                _claims_restriction = {c: None for c in csub.keys()}
            else:
                _claims_restriction = {c: None for c in _matching[0].keys()}
        else:
            _claims_restriction = {c: None for c in _matching[0].keys()}

        info = _cntxt.claims_interface.get_user_claims(
            _session_info["user_id"], claims_restriction=_claims_restriction
        )
        # create SD-JWT
        _cntxt = self.upstream_get("context")
        info = _cntxt.claims_interface.get_user_claims(
            _session_info["user_id"], claims_restriction=_claims_restriction
        )

        ci = Issuer(
            key_jar=get_keyjar(self),
            iss=self.upstream_get("attribute", "entity_id"),
            sign_alg="ES256",
            lifetime=600,
            holder_key={},
        )
        _discl = self.calculate_attribute_disclosure(info)
        if _discl:
            ci.objective_disclosure = _discl

        _discl = self.calculate_array_disclosure(info)
        if _discl:
            ci.array_disclosure = _discl

        return ci.create_holder_message(
            payload=info, jws_headers={"typ": "example+sd-jwt"}
        )


class Credential(UserInfo):
    msg_type = CredentialRequest
    response_cls = CredentialResponse
    error_msg = oidc.ResponseMessage
    request_format = "json"
    request_placement = "body"
    response_format = "json"
    response_placement = "body"
    endpoint_name = "credential_endpoint"
    name = "credential"
    endpoint_type = "oauth2"

    _supports = {
        "credentials_supported": None,
        "attribute_disclosure": None,
        "array_disclosure": None,
    }

    def __init__(self, upstream_get, conf=None, **kwargs):
        print("\nCredential Init")
        UserInfo.__init__(self, upstream_get, conf=conf, **kwargs)
        # dpop support
        self.post_parse_request.append(self.credential_request)
        if "credential_constructor" in {}:
            self.credential_constructor = execute(conf["credential_constructor"])
        else:
            self.credential_constructor = CredentialConstructor(
                upstream_get=upstream_get
            )

    def _verify_proof(self, proof):
        print("\nCredential verify proof")
        if proof["proof_type"] == "jwt":
            entity_id = self.upstream_get("attribute", "entity_id")
            key_jar = get_keyjar(self)
            # first get the key from JWT:jwk
            _jws = factory(proof["jwt"])
            key_jar.add_key(entity_id, _jws.jwt.payload()["jwk"])

            # verify key_proof
            _verifier = JWT(key_jar=key_jar)
            _payload = _verifier.unpack(proof["jwt"])
            return _payload

    def credential_request(
        self,
        request: Optional[Union[Message, dict]] = None,
        client_id: Optional[str] = "",
        http_info: Optional[dict] = None,
        auth_info: Optional[dict] = None,
        **kwargs,
    ):
        print("\nCredential request")
        """The Credential endpoint

        :param http_info: Information on the HTTP request
        :param request: The authorization request as a Message instance
        :return: dictionary
        """

        if "error" in request:
            return request

        print("\n Reached credential_request")

        _cred_request = CredentialsSupported().from_dict(request)

        _proof = Proof().from_dict(request["proof"])
        entity_id = self.upstream_get("attribute", "entity_id")
        keyjar = get_federation_entity(self).keyjar
        _proof.verify(keyjar=keyjar, aud=entity_id)
        request["proof"] = _proof
        return request

    def verify_token_and_authentication(self, request):
        print("\n verify token")
        _mngr = self.upstream_get("context").session_manager
        try:
            print("Request Token: ", request["access_token"])
            _session_info = _mngr.get_session_info_by_token(
                request["access_token"], grant=True, handler_key="access_token"
            )
        except (KeyError, ValueError):
            return self.error_cls(
                error="invalid_token", error_description="Invalid Token"
            )

        _grant = _session_info["grant"]
        token = _grant.get_token(request["access_token"])
        # should be an access token
        if token and token.token_class != "access_token":
            return self.error_cls(
                error="invalid_token", error_description="Wrong type of token"
            )

        # And it should be valid
        if token.is_active() is False:
            return self.error_cls(
                error="invalid_token", error_description="Invalid Token"
            )

        _auth_event = _grant.authentication_event
        # if the authentication is still active or offline_access is granted.
        if not _auth_event["valid_until"] >= utc_time_sans_frac():
            logger.debug(
                "authentication not valid: {} > {}".format(
                    datetime.fromtimestamp(_auth_event["valid_until"]),
                    datetime.fromtimestamp(utc_time_sans_frac()),
                )
            )
            return False, None

            # This has to be made more finegrained.
            # if "offline_access" in session["authn_req"]["scope"]:
            #     pass
        return True, _session_info["client_id"]

    def process_request(self, request=None, **kwargs):
        print("\n Credential process request")
        tokenAuthResult = self.verify_token_and_authentication(request)
        if "error" in tokenAuthResult:
            return tokenAuthResult

        allowed, client_id = tokenAuthResult
        if not isinstance(allowed, bool):
            return allowed

        if not allowed:
            return self.error_cls(
                error="invalid_token", error_description="Access not granted"
            )

        try:
            _mngr = self.upstream_get("context").session_manager
            _session_info = _mngr.get_session_info_by_token(
                request["access_token"], grant=True, handler_key="access_token"
            )
        except (KeyError, ValueError):
            return self.error_cls(
                error="invalid_token", error_description="Invalid Token"
            )

        # _msg = self.credential_constructor(
        #    user_id=_session_info["user_id"], request=request
        # )

        device_key = request["proof"]["device_publickey"]

        user_id = _session_info["user_id"]

        _msg = requests.get(
            "https://preprod.issuer.eudiw.dev/tara/R2?user_id="
            + user_id
            + "&device_publickey="
            + device_key
        ).json()

        # mdoc = "o2ZzdGF0dXMAZ3ZlcnNpb25jMS4waWRvY3VtZW50c4GiZ2RvY1R5cGV4GGV1LmV1cm9wYS5lYy5ldWRpdy5waWQuMWxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkC6TCCAuUwggJqoAMCAQICFFXdkZot2qC4PQirI0CSjtvaf85SMAoGCCqGSM49BAMCMFwxHjAcBgNVBAMMFVBJRCBJc3N1ZXIgQ0EgLSBQVCAwMTEtMCsGA1UECgwkRVVESSBXYWxsZXQgUmVmZXJlbmNlIEltcGxlbWVudGF0aW9uMQswCQYDVQQGEwJQVDAeFw0yMzA5MDIxNzQxMzNaFw0yNDExMjUxNzQxMzJaMFQxFjAUBgNVBAMMDVBJRCBEUyAtIDAwMDExLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCUFQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ7HEFK6kaZ5MnhtkaVyL8GXCCMCmbfVQMtCUZLDYdyAO2yJ5IiWRvDci8TQ7XfSyhqc7oJTZY6tDhwmnyBQ9oMo4IBEDCCAQwwHwYDVR0jBBgwFoAUapljS96vUXXkvgNDaXQofU4EEcgwFgYDVR0lAQH_BAwwCgYIK4ECAgAAAQIwQwYDVR0fBDwwOjA4oDagNIYyaHR0cHM6Ly9wcmVwcm9kLnBraS5ldWRpdy5kZXYvY3JsL3BpZF9DQV9QVF8wMS5jcmwwHQYDVR0OBBYEFPnJ9us_cLMQY_G7WO9b6bfrmKUbMA4GA1UdDwEB_wQEAwIHgDBdBgNVHRIEVjBUhlJodHRwczovL2dpdGh1Yi5jb20vZXUtZGlnaXRhbC1pZGVudGl0eS13YWxsZXQvYXJjaGl0ZWN0dXJlLWFuZC1yZWZlcmVuY2UtZnJhbWV3b3JrMAoGCCqGSM49BAMCA2kAMGYCMQDu2pq29_-BVQt6zbFR07f8P7UrMlV0bo7nNkYe-nX4fjnNpLWAyz0AweMlLEkhozQCMQDfDY3LxzmNKLJvySNY_X50eVJiKfZ3nJqnxSAO1i3rDb2ABFTyCECqfcBZNd7m9wNZArzYGFkCt6ZnZG9jVHlwZXgYZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xZ3ZlcnNpb25jMS4wbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDIzLTExLTA5VDE2OjA5OjM2Wml2YWxpZEZyb23AdDIwMjMtMTEtMDlUMTY6MDk6MzZaanZhbGlkVW50aWzAdDIwMjQtMDktMDRUMDA6MDA6MDBabHZhbHVlRGlnZXN0c6J3ZXUuZXVyb3BhLmVjLmV1ZGl3LkRFLjGhCVgg-pRSQYnzwYdO2s1RvW2EThWfnlGaPr63t-URzRwG_O54GGV1LmV1cm9wYS5lYy5ldWRpdy5waWQuMakAWCBIQVtadvh_Brwu480l65z1WIJzjO64C0MFIaOwPBUb7wFYILU3G2CRk9WwIrcp6mp2sG8mWPDq1UnU5rKYq2L39zHhAlggVX7cGWBRDxVk2yq767HITbQXegu1U4yha46quWfTknADWCDRgtKLBBXnvgOicl-gCyymO01qj_ub8b61owMaPaXOKwRYIP8ko6rQl3kASyyr8jiqZgfFR6IBbP3MOA7LMfGYgo4pBVggrhmKwmwtRxUWGrQNuNAy8yzkMmD2LruBjh_BRjaIiRwGWCApohtAUMaZVVaJfpDaxCeSaOE2JyHqCl3ctDL9X8lorQdYICt2TAljEkpZ4XGGxegx_cCS5ETA8tJOjIobHRB06FrSCFgg2zQNKbeAx-ODSpIYZu9AOozeJ1bKP-OYQJfMZzZJ6gFtZGV2aWNlS2V5SW5mb6FpZGV2aWNlS2V5pAECIAEhWCDwgRAGPgJl3diJ9eeOpGW0giIkPpaFkTESQ9SA9HL9jCJYIC54Wwk3o96HCq29TUXPbSdb1lxQsrOgqJaCGI3LfznQb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2WEAHxJI5F2p1qInDdW-Li5E30csEq2_1cEAgXrBQbmxiP54yXNAYulT3PSeT71JTXK7EBBiz__eyZ8Xs2vBnLpFEam5hbWVTcGFjZXOid2V1LmV1cm9wYS5lYy5ldWRpdy5ERS4xgdgYWJekZnJhbmRvbVggVrTRVheytPfD6ao98L7zxhBRQr6a10l1I2qUPwQzUB9oZGlnZXN0SUQJbGVsZW1lbnRWYWx1ZXgtYTM2Nzc2NjU3MjczNjk2ZjZlNjMzMTJlMzA2OTY0NmY2Mzc1NmQ2NTZlLi4ucWVsZW1lbnRJZGVudGlmaWVydHNpZ25hdHVyZV91c3VhbF9tYXJreBhldS5ldXJvcGEuZWMuZXVkaXcucGlkLjGJ2BhYg6RmcmFuZG9tWCCW7JOQWF0NpkK62uUTB4LXeXUROUZahR6L5FLIQcbzJ2hkaWdlc3RJRABsZWxlbWVudFZhbHVleCQ4NmI3M2M2Yy03NTQyLTQ5MjMtYTk4Ni05N2QyY2RmN2YwN2FxZWxlbWVudElkZW50aWZpZXJpdW5pcXVlX2lk2BhYZqRmcmFuZG9tWCDYTewK9oEsi2xHPQJnQ_1rUlhe_oXXBTpBye4EuVmMYGhkaWdlc3RJRAFsZWxlbWVudFZhbHVlYkRFcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyedgYWGykZnJhbmRvbVggtwhcHRtglOncSXptMTB2luqs1VxfNJAgjpYTLGR1Rx1oZGlnZXN0SUQCbGVsZW1lbnRWYWx1ZdkD7GoxOTY1LTAxLTAxcWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGXYGFhgpGZyYW5kb21YIM72HOl-EFcdzZlOnff0SIgZySl0lDV-7KZ7T5xO8TrlaGRpZ2VzdElEA2xlbGVtZW50VmFsdWX1cWVsZW1lbnRJZGVudGlmaWVya2FnZV9vdmVyXzE42BhYZqRmcmFuZG9tWCCdIUQP6l6Qw56QaGcPDcT1L0ukR5p6AJE8epoJFdXVW2hkaWdlc3RJRARsZWxlbWVudFZhbHVlZkdhcmNpYXFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZdgYWG6kZnJhbmRvbVggaVoesarUXDtO_Vtyi1go9I_Av24_tTPvOgIyB2gCdYhoZGlnZXN0SUQFbGVsZW1lbnRWYWx1ZdkD7GkyMDIzLTA5LTRxZWxlbWVudElkZW50aWZpZXJtaXNzdWFuY2VfZGF0ZdgYWG-kZnJhbmRvbVgg3zC26GyXf9EJ6wlz8Zc5yNHOp5h_egp07ifMvs03eiVoZGlnZXN0SUQGbGVsZW1lbnRWYWx1ZWlCdW5kZXMuLi5xZWxlbWVudElkZW50aWZpZXJxaXNzdWluZ19hdXRob3JpdHnYGFhlpGZyYW5kb21YIOwrFUFDmzRyaNM_plwKXgIRhigrkvO3H6WAYdaULXTWaGRpZ2VzdElEB2xlbGVtZW50VmFsdWVmamF2aWVycWVsZW1lbnRJZGVudGlmaWVyamdpdmVuX25hbWXYGFhspGZyYW5kb21YIJQercVQNcKNgOFuKmKzLgNiwcwwPzOCvyLi0W2jWosqaGRpZ2VzdElECGxlbGVtZW50VmFsdWXZA-xpMjAyNC0wOS00cWVsZW1lbnRJZGVudGlmaWVya2V4cGlyeV9kYXRl"

        # sd_jwt = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogInZjK3NkLWp3dCJ9.eyJpc3MiOiAiVGVzdCBQSUQgaXNzdWVyIiwgImp0aSI6ICIzOTkxYmNmZC05YWJkLTQ4NTktYjRlYy00NGU2Y2E1ZmY2ZjQiLCAiaWF0IjogMTk2NzEsICJleHAiOiAxOTY3OCwgInN0YXR1cyI6ICJleGFtcGxlIiwgInR5cGUiOiAiZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xIiwgInZlcmlmaWVkX2NsYWltcyI6IHsidmVyaWZpY2F0aW9uIjogeyJfc2QiOiBbIjU0MWFfeFRCZENMOG1TN0pPWFZYaEZhaEJPUmI1dHBQX1NYM2Y0OUVYNGMiXSwgInRydXN0X2ZyYW1ld29yayI6ICJlaWRhcyIsICJhc3N1cmFuY2VfbGV2ZWwiOiAiaGlnaCJ9LCAiY2xhaW1zIjogeyJldS5ldXJvcGEuZWMuZXVkaXcucGlkLjEiOiB7Il9zZCI6IFsiNk5MMDY5ZmFfOGpFY2M2LW9yLVo1ejNZM3RnOGw2dDVoTFpwSG5lTmY1dyIsICJCZkhldW5vdWg4RWkwbnd5TEx5VkxXUVc5b2JsTHg1N0RraklTUG9nQ3hZIiwgIkxTTW5HSTl2SW9qbTh4VVpGZVFPa1NVSlF6X3hUdzRFdnVQR0hHbzd5eWciLCAiVHBhdXdOcExjZmxtZnNPU05zcENQV29iNG1mQkFIMHFscjNkNGtkRWk3QSIsICJWeEdxQmVBU1dYMjViMS1YbUpJcWstbWZield6TUxQdWlFTlozc0hrS1lVIiwgImR4VlVDWi0ycUpVTnJvb25PaU5pTFFSSUMyMDFFeFgwRFlleVhIUURrTzAiLCAibWVHeEpNVGo3WWZnRVNzLTlVbTFWT09EWjBGVDF1Z0h4RzFfeERsNWpaYyIsICJyWVhJZnR3QUk2ZVhaTENqOHpzTHBPYVhRQkFSb1BEYWIwZzdSSERtNDdRIiwgInk4SUFfYnVzZW1qTExpVkR1cmxfcUI2Z2hwcEMwNzg1UkVEdnZMVC11QlEiXX19fSwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogInVGd0dNN1VuMDJHNUYxa0o1b3lZTXdyTnlUYUw0b0F6MXhmWm9xcnNSTVU9IiwgInkiOiAiVnRBMVZyVU9Wa1JoenFNVVN0aGNGNEw2QllRajdkUmk0TU1neVdydUtwOD0ifX19.GoKcM-KviKyZWeFvUuZMJE8Klx3QxQCOOoIY2-0K_eTDNKTlu8oV2qUM-snHT7Zug9OXP-mjbpNGNJ2gaGJMIQ~WyJQaWptWkg3WFpjbHRpaUE0emlXeUlRIiwgImV2aWRlbmNlIiwgeyJ0eXBlIjogImxpbmsgZG8gaXNzdWVyIiwgInNvdXJjZSI6IHsib3JnYW5pemF0aW9uX25hbWUiOiAiVGVzdCBQSUQgaXNzdWVyIiwgIm9yZ2FuaXphdGlvbl9pZCI6ICJJUEEgQ29kZSIsICJjb3VudHJ5X2NvZGUiOiAiRkMifX1d~WyJFdy1iWmhSOUZaMm85TVZqbGNRZXB3IiwgImZhbWlseV9uYW1lIiwgImphdmllciJd~WyJNb2UtbVlBaUNub1l3blQ5MHBQSHh3IiwgImdpdmVuX25hbWUiLCAiR2FyY2lhIl0~WyIyQUJ5UTNWZHNLTEtHNkI5TFJYSVJBIiwgImJpcnRoX2RhdGUiLCAiMTk2NS0wMS0wMSJd~WyJJNll3SGxONmU1bmU2OHFQMU41cS13IiwgInVuaXF1ZV9pZCIsICI4NmI3M2M2Yy03NTQyLTQ5MjMtYTk4Ni05N2QyY2RmN2YwN2EiXQ~WyJ0QWlDanNhZHRxNWgtdjJtV1VqRWJ3IiwgImFnZV9vdmVyXzE4IiwgdHJ1ZV0~WyI5SEVtdHByZ0FlZ1ZQWnQ4Y2IyR21BIiwgImlzc3VhbmNlX2RhdGUiLCAiMjAyMy0xMS0xMCJd~WyJVUGcyQzlXbUZJY3pvZDFtcmZtVkV3IiwgImV4cGlyeV9kYXRlIiwgIjIwMjMtMTEtMTciXQ~WyJ6S05BYmNUNUVVZzZVN0xvYkFmdUZ3IiwgImlzc3VpbmdfYXV0aG9yaXR5IiwgIlRlc3QgUElEIGlzc3VlciJd~WyIySnJOamsxa01ETVJPMTRLSUFDTWlnIiwgImlzc3VpbmdfY291bnRyeSIsICJGQyJd~"

        # _msg = {"mdoc": mdoc, "sd-jwt": sd_jwt}

        _resp = {
            "format": "vc+mdoc+sd-jwt",
            "credential": _msg,
            "c_nonce": rndstr(),
            "c_nonce_expires_in": 86400,
        }
        print("\nResp:", _resp)
        return {"response_args": _resp, "client_id": client_id}
