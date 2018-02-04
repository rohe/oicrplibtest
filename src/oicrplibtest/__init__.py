import cherrypy
import logging
import sys
import traceback
from importlib import import_module

from cryptojwt import as_bytes

from oiccli.client_auth import CLIENT_AUTHN_METHOD
from oiccli import oauth2
from oiccli import oic

from oicrp import provider
from oicrp.oic import Client

__author__ = 'Roland Hedberg'
__version__ = '0.0.2'

logger = logging.getLogger(__name__)


class HandlerError(Exception):
    pass


class ConfigurationError(Exception):
    pass


def token_secret_key(sid):
    return "token_secret_%s" % sid


SERVICE_NAME = "OIC"
CLIENT_CONFIG = {}


def do_request(client, srv, scope="", response_body_type="",
               method="", request_args=None, extra_args=None,
               http_args=None, authn_method="", **kwargs):
    if not method:
        method = srv.http_method

    _info = srv.do_request_init(
        client.client_info, method=method, scope=scope,
        request_args=request_args, extra_args=extra_args,
        authn_method=authn_method, http_args=http_args, **kwargs)

    try:
        _body = _info['body']
    except KeyError:
        _body = None

    if not response_body_type:
        response_body_type = srv.response_body_type

    logger.debug('do_request info: {}'.format(_info))

    try:
        kwargs['state'] = request_args['state']
    except KeyError:
        pass

    return client.service_request(srv, _info['uri'], method, _body,
                                  response_body_type,
                                  http_args=_info['http_args'],
                                  client_info=client.client_info, **kwargs)


class RPHandler(object):
    def __init__(self, base_url='', hash_seed="", jwks=None, verify_ssl=False,
                 services=None, service_factory=None, client_configs=None,
                 client_authn_method=CLIENT_AUTHN_METHOD, client_cls=None,
                 jwks_path='', jwks_uri='', **kwargs):
        self.base_url = base_url
        self.hash_seed = as_bytes(hash_seed)
        self.verify_ssl = verify_ssl
        self.jwks = jwks

        self.extra = kwargs

        self.client_cls = client_cls or Client
        self.services = services
        self.service_factory = service_factory or factory
        self.client_authn_method = client_authn_method
        self.client_configs = client_configs
        self.jwks_path = jwks_path
        self.jwks_uri = jwks_uri

        # keep track on which RP instance that serves with OP
        self.test_id2rp = {}

    def state2issuer(self, state):
        for iss, rp in self.test_id2rp.items():
            if state in rp.client_info.state_db:
                return iss

    def pick_config(self, issuer):
        try:
            return self.client_configs[issuer]
        except KeyError:
            return self.client_configs['']

    def run(self, client, state=''):
        _srvs = client.client_info.config['services']
        while client.client_info.service_index < len(_srvs):
            srv, conf = _srvs[client.client_info.service_index]
            _srv = self.service_factory(
                srv, httplib=client.http, keyjar=client.client_info.keyjar,
                client_authn_method=self.client_authn_method, conf=conf)

            if _srv.endpoint_name:
                _srv.endpoint = client.client_info.provider_info[
                    _srv.endpoint_name]

            if _srv.synchronous is True:
                req_args = {}
                kwargs = {}
                if state:
                    if _srv.endpoint_name == 'token_endpoint':
                        req_args = {
                            'state': state,
                            'redirect_uri': client.client_info.redirect_uris[0]}
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

                client.client_info.service_index += 1
            else:
                _info = _srv.request_info(client.client_info)
                raise cherrypy.HTTPRedirect(_info['uri'])

        return b'OK'

    def phase0(self, test_id):
        """
        If no client exists for this issuer one is created and initiated with
        the necessary information for them to be able to communicate.

        :param test_id: The Test ID
        :return: A :py:class:`oiccli.oic.Client` instance
        """
        try:
            client = self.test_id2rp[test_id]
        except KeyError:
            _cnf = self.pick_config(test_id)

            try:
                _services = _cnf['services']
            except KeyError:
                _services = self.services

            try:
                client = self.client_cls(
                    client_authn_method=self.client_authn_method,
                    verify_ssl=self.verify_ssl, services=_services,
                    service_factory=self.service_factory, config=_cnf)
            except Exception as err:
                logger.error('Failed initiating client: {}'.format(err))
                message = traceback.format_exception(*sys.exc_info())
                logger.error(message)
                raise

            client.client_info.base_url = self.base_url
            client.client_info.service_index = 0
            client.client_info.keyjar.import_jwks_as_json(self.jwks, '')
            self.test_id2rp[test_id] = client

        return self.run(client)

    @staticmethod
    def get_response_type(client, issuer):
        return client.client_info.behaviour['response_types'][0]

    @staticmethod
    def get_client_authn_method(client, endpoint):
        if endpoint == 'token_endpoint':
            try:
                am = client.client_info.behaviour['token_endpoint_auth_method']
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

        _srvs = client.client_info.config['services']

        srv, conf = _srvs[client.client_info.service_index]
        _srv = self.service_factory(
            srv, httplib=client.http, keyjar=client.client_info.keyjar,
            client_authn_method=self.client_authn_method, conf=conf)

        try:
            authresp = _srv.parse_response(response, client.client_info,
                                           sformat='dict')
        except Exception as err:
            logger.error('Parsing authresp: {}'.format(err))
            raise
        else:
            logger.debug('Authz response: {}'.format(authresp.to_dict()))

        client.client_info.service_index += 1

        return self.run(client, state=response['state'])


def get_service_unique_request(service, request, **kwargs):
    """
    Get a class instance of a :py:class:`oiccli.request.Request` subclass
    specific to a specified service

    :param service: The name of the service
    :param request: The name of the request
    :param kwargs: Arguments provided when initiating the class
    :return: An initiated subclass of oiccli.request.Request or None if
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
            oic.service.factory(req_name[1], **kwargs)
        else:
            return get_service_unique_request(req_name[0], req_name[1],
                                              **kwargs)
    else:
        return oic.service.factory(req_name, **kwargs)
