__author__ = "Roland Hedberg"
__version__ = "0.1.0"

from typing import Any
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import factory
from fedservice.server import ServerUnit
from idpyoidc.configure import Base
from idpyoidc.server import ASConfiguration
from idpyoidc.server import authz
from idpyoidc.server import build_endpoints
from idpyoidc.server import Endpoint
from idpyoidc.server import EndpointContext
from idpyoidc.server.claims.oauth2 import Claims as OAUTH2_Claims
from idpyoidc.server.client_authn import client_auth_setup
from idpyoidc.server.endpoint_context import init_service
from idpyoidc.server.user_authn.authn_context import populate_authn_broker


ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation"

def do_endpoints(conf, upstream_get):
    _endpoints = conf.get("endpoint")
    if _endpoints:
        return build_endpoints(_endpoints, upstream_get=upstream_get, issuer=conf["issuer"])
    else:
        return {}


class ServerEntity(ServerUnit):
    name = 'eudi_server'
    parameter = {"endpoint": [Endpoint], "context": EndpointContext}
    claims_class = OAUTH2_Claims

    def __init__(
            self,
            config: Optional[Union[dict, ASConfiguration]] = None,
            upstream_get: Optional[Callable] = None,
            keyjar: Optional[KeyJar] = None,
            cwd: Optional[str] = "",
            cookie_handler: Optional[Any] = None,
            httpc: Optional[Any] = None,
            httpc_params: Optional[dict] = None,
            entity_id: Optional[str] = "",
            key_conf: Optional[dict] = None
    ):
        if config is None:
            config = {}

        ServerUnit.__init__(self, upstream_get=upstream_get, keyjar=keyjar, httpc=httpc,
                            httpc_params=httpc_params, entity_id=entity_id, key_conf=key_conf,
                            config=config)

        if not isinstance(config, Base):
            config['issuer'] = entity_id
            config['base_url'] = entity_id
            config = ASConfiguration(config)

        self.config = config

        self.endpoint = do_endpoints(config, self.unit_get)
        server_type = config.get("server_type", config["conf"].get("server_type", ""))

        self.context = EndpointContext(
            conf=config,
            upstream_get=self.unit_get,
            cwd=cwd,
            cookie_handler=cookie_handler,
            httpc=httpc,
            claims_class=self.claims_class(),
            server_type=server_type
        )

        self.context.claims_interface = init_service(
            config["claims_interface"], self.unit_get
        )

        self.context.do_add_on(endpoints=self.endpoint)

    def get_endpoints(self, *arg):
        return self.endpoint

    def get_endpoint(self, endpoint_name, *arg):
        try:
            return self.endpoint[endpoint_name]
        except KeyError:
            return None

    def get_context(self, *arg):
        return self.context

    def get_server(self, *args):
        return self

    def get_metadata(self, *args):
        # static ! Should this be done dynamically ?
        if args:
            return {args[0]: self.context.provider_info}
        else:
            return {'openid_provider': self.context.provider_info}

    def setup_authz(self):
        authz_spec = self.config.get("authz")
        if authz_spec:
            return init_service(authz_spec, self.unit_get)
        else:
            return authz.Implicit(self.unit_get)

    def setup_authentication(self, target):
        _conf = self.config.get("authentication")
        if _conf:
            target.authn_broker = populate_authn_broker(
                _conf, self.unit_get, target.template_handler
            )
        else:
            target.authn_broker = {}

        target.endpoint_to_authn_method = {}
        for method in target.authn_broker:
            try:
                target.endpoint_to_authn_method[method.action] = method
            except AttributeError:
                pass

    def setup_client_authn_methods(self):
        self.context.client_authn_methods = client_auth_setup(
            self.unit_get, self.config.get("client_authn_methods")
        )

def extract_key_from_jws(token):
    # key can be in cnf:jwk in payload or jwk in header
    _jws = factory(token)
    _jwk = _jws.jwt.headers.get("jwk", None)
    if _jwk is None:
        _payload = _jws.jwt.payload()
        _jwk = _payload['cnf'].get('jwk', None)
    if _jwk:
        return key_from_jwk_dict(_jwk)
    else:
        return None

def jws_issuer(token):
    _jws = factory(token)
    return _jws.jwt.payload()["iss"]
