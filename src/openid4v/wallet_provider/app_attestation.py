import base64
import json
import logging
from typing import Optional

import cryptography
from cryptojwt import as_unicode
from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.encrypter import default_crypt_config
from idpyoidc.encrypter import init_encrypter
from idpyoidc.message import Message
from idpyoidc.server import Endpoint
from idpyoidc.server.util import execute
from idpyoidc.server.util import lv_pack
from idpyoidc.server.util import lv_unpack
from idpyoidc.util import rndstr

from openid4v.message import AppAttestationResponse
from openid4v.wallet_provider.token import InvalidNonce

logger = logging.getLogger(__name__)


class AppAttestationService(object):

    def __init__(self, upstream_get,
                 crypt_config: Optional[dict] = None,
                 nonce_lifetime: Optional[int] = 300
                 ):
        self.upstream_get = upstream_get
        if crypt_config is None:
            crypt_config = default_crypt_config()

        _crypt = init_encrypter(crypt_config)
        self.crypt = _crypt["encrypter"]
        self.nonce_lifetime = nonce_lifetime

    def __call__(self, iccid):
        # create an encrypted statement
        rnd = rndstr(32)
        info = json.dumps({
            "iss": self.upstream_get("attribute", "entity_id"),
            "iccid": iccid,
            "exp": utc_time_sans_frac() + self.nonce_lifetime
        })
        nonce = base64.b64encode(
            self.crypt.encrypt(lv_pack(rnd, info).encode())
        ).decode("utf-8")

        return nonce

    def verify_nonce(self, nonce):
        try:
            plain = self.crypt.decrypt(base64.b64decode(nonce))
        except cryptography.fernet.InvalidToken as err:
            logger.error(f"cryptography.fernet.InvalidToken: {nonce}")
            raise InvalidNonce(err)
        except Exception as err:
            logger.error(f"Other decrypt error ({err}), nonce={nonce}")
            raise InvalidNonce(err)
        # order: rnd, info
        part = lv_unpack(as_unicode(plain))
        info = json.loads(part[1])
        if info["iss"] != self.upstream_get("attribute", "entity_id"):
            logger.error("Wrong issuer")
            raise InvalidNonce("Wrong Issuer")
        _now = utc_time_sans_frac()
        if _now > info["exp"]:
            logger.error("Nonce is too old")
            raise InvalidNonce("Too old")
        return info["iccid"]


class AppAttestation(Endpoint):
    request_cls = Message
    response_cls = AppAttestationResponse
    request_format = ""
    response_format = "json"
    name = "app_attestation"
    endpoint_type = "oauth2"
    endpoint_name = "app_attestation_endpoint"
    response_content_type = "application/json"

    def __init__(self, upstream_get, conf=None, **kwargs):
        Endpoint.__init__(self, upstream_get, conf=conf, **kwargs)
        if conf and "app_attestation_service" in conf:
            self.attestation_service = execute(conf["app_attestation_service"])
        else:
            self.attestation_service = AppAttestationService(upstream_get=upstream_get)

    def process_request(self, request=None, **kwargs):
        _msg = {"nonce": self.attestation_service(iccid=request["iccid"])}
        return {"response_msg": json.dumps(_msg)}
