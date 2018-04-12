import cherrypy
import logging
import sys
import traceback
from importlib import import_module

from cryptojwt import as_bytes
from oidcmsg.key_jar import KeyJar

from oidcservice import oauth2
from oidcservice import oidc

from oidcrp import provider, InMemoryStateDataBase
from oidcservice.state_interface import StateInterface
from oidcrp import provider
from oidcrp.oidc import RP

__author__ = 'Roland Hedberg'
__version__ = '0.0.2'

logger = logging.getLogger(__name__)


class HandlerError(Exception):
    pass


class ConfigurationError(Exception):
    pass


def token_secret_key(sid):
    return "token_secret_%s" % sid


SERVICE_ORDER = ['WebFinger', 'ProviderInfoDiscovery', 'Registration',
                 'Authorization', 'AccessToken', 'RefreshAccessToken',
                 'UserInfo']
SERVICE_NAME = "OIC"
CLIENT_CONFIG = {}


def do_request(client, srv, scope="", response_body_type="",
               method="", request_args=None, extra_args=None,
               http_args=None, authn_method="", **kwargs):
    if not method:
        method = srv.http_method

    _info = srv.get_request_parameters(
        method=method, scope=scope, request_args=request_args,
        extra_args=extra_args, authn_method=authn_method, http_args=http_args,
        **kwargs)

    if not response_body_type:
        response_body_type = srv.response_body_type

    logger.debug('do_request info: {}'.format(_info))

    try:
        kwargs['state'] = request_args['state']
    except KeyError:
        pass

    kwargs.update(_info)
    return client.service_request(srv, response_body_type=response_body_type,
                                  **kwargs)


class RPHandler(object):
    def __init__(self, base_url='', hash_seed="", jwks=None, verify_ssl=False,
                 service_factory=None, client_configs=None,
                 client_authn_factory=None, client_cls=None,
                 jwks_path='', jwks_uri='', **kwargs):
        self.base_url = base_url
        self.hash_seed = as_bytes(hash_seed)
        self.verify_ssl = verify_ssl
        self.jwks = jwks

        if state_db is None:
            self.state_db = InMemoryStateDataBase()
        else:
            self.state_db = state_db

        self.state_db_interface = StateInterface(self.state_db)

        self.extra = kwargs

        self.client_cls = client_cls or RP
        self.service_factory = service_factory or factory
        self.client_authn_factory = client_authn_factory
        self.client_configs = client_configs
        self.jwks_path = jwks_path
        self.jwks_uri = jwks_uri

        # keep track on which RP instance that serves with OP
        self.test_id2rp = {}

    def state2issuer(self, state):
        return self.state_db_interface.get_iss(state)

    def pick_config(self, issuer):
        try:
            return self.client_configs[issuer]
        except KeyError:
            return self.client_configs['']

    def run(self, client, state=''):
        client.service_context.service_index = 0
        while client.service_context.service_index < len(SERVICE_ORDER):
            _service = SERVICE_ORDER[client.service_context.service_index]
            try:
                conf = client.service_context.config["services"][_service]
            except KeyError:
                client.service_context.service_index += 1
                continue

            _srv = self.service_factory(
                _service, service_context=client.service_context,
                client_authn_factory=self.client_authn_factory,
                state=client.state_db, conf=conf)

            if _srv.endpoint_name:
                _srv.endpoint = client.service_context.provider_info[
                    _srv.endpoint_name]

            if _srv.synchronous is True:
                req_args = {}
                kwargs = {}
                if state:
                    if _srv.endpoint_name == 'token_endpoint':
                        req_args = {
                            'state': state,
                            'redirect_uri':
                                client.service_context.redirect_uris[0]}
                    elif _srv.endpoint_name == 'userinfo_endpoint':
                        kwargs = {'state': state}

                try:
                    do_request(client, _srv, request_args=req_args, **kwargs)
                except Exception as err:
                    message = traceback.format_exception(*sys.exc_info())
                    logger.error(message)
                    _header = '<h2>{} ({})</h2>'.format(err,
                                                        err.__class__.__name__)
                    _body = '<br>'.join(message)
                    _error_html = '{}<p>{}</p>'.format(_header, _body)
                    return as_bytes(_error_html)

                client.service_context.service_index += 1
            else:
                _info = _srv.request_info(client.service_context)
                raise cherrypy.HTTPRedirect(_info['uri'])

        return b'OK'

    def phase0(self, test_id):
        """
        If no client exists for this issuer one is created and initiated with
        the necessary information for it to be able to communicate.

        :param test_id: The Test ID
        :return: A :py:class:`oidcrp.oidc.Client` instance
        """
        try:
            client = self.test_id2rp[test_id]
        except KeyError:
            _cnf = self.pick_config(test_id)
            _services = _cnf['services']
            keyjar = KeyJar()
            keyjar.import_jwks_as_json(self.jwks, '')
            try:
                client = self.client_cls(keyjar=keyjar, state_db=self.state_db,
                    client_authn_factory=self.client_authn_factory,
                    verify_ssl=self.verify_ssl, services=_services,
                    service_factory=self.service_factory, config=_cnf)
            except Exception as err:
                logger.error('Failed initiating client: {}'.format(err))
                message = traceback.format_exception(*sys.exc_info())
                logger.error(message)
                raise

            client.service_context.base_url = self.base_url
            client.service_context.service_index = 0
            client.service_context.keyjar.import_jwks_as_json(self.jwks, '')
            self.test_id2rp[test_id] = client

        return self.run(client)

    @staticmethod
    def get_response_type(client, issuer):
        return client.service_context.behaviour['response_types'][0]

    @staticmethod
    def get_client_authn_method(client, endpoint):
        if endpoint == 'token_endpoint':
            try:
                am = client.service_context.behaviour[
                    'token_endpoint_auth_method']
            except KeyError:
                am = ''
            else:
                if isinstance(am, str):
                    return am
                else:
                    return am[0]

    # noinspection PyUnusedLocal
    def phaseN(self, client, response):
        """Step 2: Once the consumer has redirected the user back to the
        callback URL you can request the access token the user has
        approved.

        :param issuer: Who sent the response
        :param response: The response in what ever format it was received
        """

        _srvs = client.service_context.config['services']

        srv, conf = _srvs[client.service_context.service_index]
        _srv = self.service_factory(
            srv, httplib=client.http, keyjar=client.service_context.keyjar,
            client_authn_factory=self.client_authn_factory, conf=conf)

        try:
            authresp = _srv.parse_response(response, client.service_context,
                                           sformat='dict')
        except Exception as err:
            logger.error('Parsing authresp: {}'.format(err))
            raise
        else:
            logger.debug('Authz response: {}'.format(authresp.to_dict()))

        client.service_context.service_index += 1

        return self.run(client, state=response['state'])


def get_service_unique_request(service, request, **kwargs):
    """
    Get a class instance of a :py:class:`oidcservice.request.Request` subclass
    specific to a specified service

    :param service: The name of the service
    :param request: The name of the request
    :param kwargs: Arguments provided when initiating the class
    :return: An initiated subclass of oidcservice.request.Request or None if
        the service or the request could not be found.
    """
    if service in provider.__all__:
        mod = import_module('oicrp.provider.' + service)
        cls = getattr(mod, request)
        return cls(**kwargs)

    return None


def factory(req_name, **kwargs):
    if isinstance(req_name, tuple):
        if req_name[0] == 'oauth2':
            oauth2.service.factory(req_name[1], **kwargs)
        elif req_name[0] == 'oidc':
            oidc.service.factory(req_name[1], **kwargs)
        else:
            return get_service_unique_request(req_name[0], req_name[1],
                                              **kwargs)
    else:
        return oidc.service.factory(req_name, **kwargs)
