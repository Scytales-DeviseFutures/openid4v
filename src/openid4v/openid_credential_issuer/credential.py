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

import json
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import base64


logger = logging.getLogger(__name__)


def get_keyjar(unit):
    _fed = get_federation_entity(unit)
    if _fed:
        return _fed.keyjar
    else:
        return unit.upstream_get("attribute", "keyjar")


class CredentialConstructor(object):
    def __init__(self, upstream_get, **kwargs):
        self.upstream_get = upstream_get

    def calculate_attribute_disclosure(self, info):
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
        """The Credential endpoint

        :param http_info: Information on the HTTP request
        :param request: The authorization request as a Message instance
        :return: dictionary
        """

        if "error" in request:
            return request

        _cred_request = CredentialsSupported().from_dict(request)

        _proof = Proof().from_dict(request["proof"])
        entity_id = self.upstream_get("attribute", "entity_id")
        keyjar = get_federation_entity(self).keyjar
        _proof.verify(keyjar=keyjar, aud=entity_id)
        request["proof"] = _proof
        return request

    def verify_token_and_authentication(self, request):
        _mngr = self.upstream_get("context").session_manager
        try:
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

    # gets the public key from a JWK
    def pKfromJWK(self, jwt_encoded):
        jwt_decoded = jwt.get_unverified_header(jwt_encoded)
        jwk = jwt_decoded["jwk"]

        if "crv" not in jwk or jwk["crv"] != "P-256":
            _resp = {
                "error": "invalid_proof",
                "error_description": "Credential Issuer only supports P-256 curves",
                "c_nonce": rndstr(),
                "c_nonce_expires_in": 86400,
            }
            return _resp  # {"response_args": _resp, "client_id": client_id}

        x = jwk["x"]
        y = jwk["y"]

        # Convert string coordinates to bytes
        x_bytes = base64.urlsafe_b64decode(x + "=" * (4 - len(x) % 4))
        y_bytes = base64.urlsafe_b64decode(y + "=" * (4 - len(y) % 4))

        # Create a public key from the bytes
        public_numbers = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(x_bytes, "big"),
            y=int.from_bytes(y_bytes, "big"),
            curve=ec.SECP256R1(),
        )

        public_key = public_numbers.public_key()

        # Serialize the public key to PEM format
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Encode the public key in base64url format

        device_key = base64.urlsafe_b64encode(public_key_pem).decode("utf-8")

        return device_key

    def singleCredential(self, request):
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

        if "proof" not in request:
            _resp = {
                "error": "invalid_proof",
                "error_description": "Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce.",
            }
            return _resp, client_id  # {"response_args": _resp, "client_id": client_id}

        jwt_encoded = request["proof"]["jwt"]

        device_key = self.pKfromJWK(jwt_encoded)
        if "error" in device_key:
            return device_key, client_id

        user_id = _session_info["user_id"]

        info = user_id.split(".", 1)

        redirect_uri = ""
        if "doctype" not in request or "oidc_config" not in request:
            _resp = {
                "error": "invalid_credential_request",
                "error_description": "Missing doctype",
            }
            return _resp, client_id  # {"response_args": _resp, "client_id": client_id}

        doc_country = request["doctype"] + "." + info[0]
        redirect_uri = request["oidc_config"].credential_urls[doc_country]

        _msg = requests.get(
            redirect_uri + "?user_id=" + info[1] + "&device_publickey=" + device_key,
            verify=False,
        ).json()

        credentialformat = request["format"]

        if credentialformat == "mso_mdoc":
            msg = _msg["mdoc"]
        elif credentialformat == "vc+sd-jwt":
            msg = _msg["sd-jwt"]
        else:
            return self.error_cls(
                error="invalid format", error_description="invalid format"
            )

        _resp = {
            "credential": msg,
        }

        return _resp, client_id

    def batchCredential(self, request):
        credentials = {"credential_responses": []}

        for credential in request["credential_requests"]:
            credential["oidc_config"] = request["oidc_config"]
            credential["access_token"] = request["access_token"]

            single_resp, client_id = self.singleCredential(credential)
            credentials["credential_responses"].append(single_resp)

        return credentials, client_id

    def credentialReq(self, request):
        print(request["credential_requests"])

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

        for credential in request["credential_requests"]:
            if "proof" not in credential:
                _resp = {
                    "error": "invalid_proof",
                    "error_description": "Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce.",
                }
                return (
                    _resp,
                    client_id,
                )  # {"response_args": _resp, "client_id": client_id}

            if "doctype" not in credential or "oidc_config" not in request:
                _resp = {
                    "error": "invalid_credential_request",
                    "error_description": "Missing doctype",
                }
                return (
                    _resp,
                    client_id,
                )  # {"response_args": _resp, "client_id": client_id}

        for credential in request["credential_requests"]:
            jwt_encoded = credential["proof"]["jwt"]
            device_key = self.pKfromJWK(jwt_encoded)
            if "error" in device_key:
                return device_key, client_id
            credential["device_publickey"] = device_key

        user_id = _session_info["user_id"]

        info = user_id.split(".", 1)

        # doc_country = request["doctype"] + "." + info[0]
        redirect_uri = request["oidc_config"].credential_urls["dynamic"]

        print(
            "\n---------Credential Request-------------\n",
            request["credential_requests"],
        )

        """ _msg = requests.get(
            redirect_uri
            + "?user_id="
            + info[1]
            + "&credential_requests="
            + json.dumps(request["credential_requests"]),
            verify=False,
        ).json() """

        data = {
            "credential_requests": request["credential_requests"],
            "user_id": info[1],
        }

        json_data = json.dumps(data)
        headers = {"Content-Type": "application/json"}
        _msg = requests.post(
            redirect_uri, data=json_data, headers=headers, verify=False
        ).json()

        """ credentialformat = request["format"]

        if credentialformat == "mso_mdoc":
            msg = _msg["mdoc"]
        elif credentialformat == "vc+sd-jwt":
            msg = _msg["sd-jwt"]
        else:
            return self.error_cls(
                error="invalid format", error_description="invalid format"
            ) """

        credentials = {"credential_responses": []}
        for credential in _msg:
            credentials["credential_responses"].append({credential: _msg[credential]})

        return credentials, client_id

    def process_request(self, request=None, **kwargs):
        # _msg = self.credential_constructor(
        #    user_id=_session_info["user_id"], request=request
        # )

        if "credential_requests" in request:
            credentials, client_id = self.credentialReq(request)
        else:
            credentials, client_id = self.singleCredential(request)

        # credentials, client_id = self.credentialReq(request)
        _resp = {
            "c_nonce": rndstr(),
            "c_nonce_expires_in": 86400,
        }

        _resp.update(credentials)

        logger.info("Response: ", _resp)
        return {"response_args": _resp, "client_id": client_id}
