import json
import logging
import os
import sys
import traceback
from urllib.parse import urlparse

from cryptojwt import KeyJar
from cryptojwt import as_unicode
from cryptojwt.utils import as_bytes
from oidcmsg.exception import MessageException
from oidcmsg.exception import NotForMe
from oidcmsg.oidc import verified_claim_name
from oidcmsg.oidc.session import BackChannelLogoutRequest
from oidcrp import InMemoryStateDataBase
from oidcrp.oidc import RP
from oidcservice.service_factory import service_factory
from oidcservice.state_interface import StateInterface

__author__ = 'Roland Hedberg'
__version__ = '0.2.0'

logger = logging.getLogger(__name__)


class HandlerError(Exception):
    pass


class ConfigurationError(Exception):
    pass


def token_secret_key(sid):
    return "token_secret_%s" % sid


SERVICE_ORDER = ['WebFinger', 'ProviderInfoDiscovery', 'Registration',
                 'Authorization', 'AccessToken', 'RefreshAccessToken',
                 'UserInfo', 'EndSession']

RT = {
    "CNF": 'code',
    "DYN": 'code',
    "C": 'code',
    "CI": 'code id_token',
    "CT": 'code token',
    "CIT": "code id_token token",
    "I": 'id_token',
    "IT": 'id_token token'
    }


def get_clients(profile, response_type, op, rp, profile_file):
    """
    Construct the configurations for all the 'OPs' = tests that is expected
    to be executed.

    :param profile: The profile that is to be tested, defines which tests are
        to be run
    :param response_type: Which response_type to use
    :param op: The issuer ID for the OP (= the testtool)
    :param rp: The base URL for the RP (= this entity)
    :param profile_file: 'full.json' (=ALL) or 'mti.json'
        (=only MTI functionality)
    :return: Dictionary with all the configurations keyed by the test ID.
    """
    profile_tests = json.loads(open(profile_file).read())[profile]
    conf = {}
    test_dir = "test_conf"
    for test_id in profile_tests:
        fname = os.path.join(test_dir, "{}.json".format(test_id))
        _cnf = json.loads(open(fname).read())
        try:
            _iss = _cnf['issuer'].replace('<OP>', op)
        except KeyError:
            _res = _cnf['resource']
            if '<OP>' in _res:
                _res = _res.replace('<OP>', op)
            else:
                p = urlparse(op)
                _res = _res.replace('<OP_HOST>', p.netloc)
            _res = _res.replace('oicrp', 'oidcrp_{}'.format(profile))
            _cnf['resource'] = _res
        else:
            _cnf['issuer'] = _iss.replace('oicrp', 'oidcrp_{}'.format(profile))

        try:
            ru = _cnf['redirect_uris']
        except KeyError:
            pass
        else:
            ru = [u.replace('<RP>', rp) for u in ru]
            if response_type == 'code':
                ru = [u.replace('ihf_cb', 'authz_cb') for u in ru]
            _cnf['redirect_uris'] = ru

        try:
            rt = _cnf['client_preferences']['response_types']
        except KeyError:
            pass
        else:
            rt = [x.replace('<RESPONSE_TYPE>', response_type) for x in rt]
            _cnf['client_preferences']['response_types'] = rt

        for _uri in ['jwks_uri', 'backchannel_logout_uri',
                     'frontchannel_logout_uri']:
            try:
                ju = _cnf[_uri]
            except KeyError:
                pass
            else:
                _cnf[_uri] = ju.replace('<RP>', rp)

        try:
            ru = _cnf['post_logout_redirect_uris']
        except KeyError:
            pass
        else:
            ru = [u.replace('<RP>', rp) for u in ru]
            _cnf['post_logout_redirect_uris'] = ru

        if 'code' not in response_type:
            try:
                del _cnf['services']['AccessToken']
            except KeyError:
                pass
        if response_type == 'id_token':
            try:
                del _cnf['services']['UserInfo']
            except KeyError:
                pass

        conf[test_id] = _cnf
    return conf


def do_request(client, srv, scope="", response_body_type="", method="",
               request_args=None, http_args=None, authn_method="", **kwargs):
    """
    As a client send a request to the OP and handle the response.

    :param client: The client
    :param srv: The OP that should receive the request
    :param scope: Which scope to use.
    :param response_body_type: The body type of the response
    :param method: Which HTTP method to use for sending the request
    :param request_args: Request arguments
    :param http_args: HTTP arguments
    :param authn_method: Which client authentication method to use
    :param kwargs: Extra keyword arguments.
    :return: The response
    """
    if not method:
        method = srv.http_method

    _info = srv.get_request_parameters(
        method=method, scope=scope, request_args=request_args,
        authn_method=authn_method, http_args=http_args, **kwargs)

    if not response_body_type:
        response_body_type = srv.response_body_type

    logger.debug('do_request info: {}'.format(_info))


    # map states

    if srv.endpoint_name == 'end_session_endpoint':
        client.session_interface.store_logout_state2state(request_args['state'],
                                                          kwargs['state'])

    try:
        kwargs['state'] = request_args['state']
    except KeyError:
        pass

    kwargs.update(_info)
    return client.service_request(srv, response_body_type=response_body_type,
                                  **kwargs)


class RPHandler(object):
    def __init__(self, base_url='', hash_seed="", verify_ssl=False,
                 service_factory=None, client_configs=None, state_db=None,
                 client_authn_factory=None, client_cls=None, keyjar=None,
                 jwks_path='', jwks_uri='', template_handler=None, **kwargs):
        self.base_url = base_url
        self.hash_seed = as_bytes(hash_seed)
        self.verify_ssl = verify_ssl
        self.keyjar = keyjar

        if state_db is None:
            self.state_db = InMemoryStateDataBase()
        else:
            self.state_db = state_db

        self.session_interface = StateInterface(self.state_db)

        self.extra = kwargs

        self.client_cls = client_cls or RP
        self.service_factory = service_factory or factory
        self.client_authn_factory = client_authn_factory
        self.client_configs = client_configs
        self.jwks_path = jwks_path
        self.jwks_uri = jwks_uri
        self.template_handler = template_handler

        # keep track on which RP instance that serves with OP
        self.test_id2rp = {}
        self.issuer2rp = {}

    def state2issuer(self, state):
        return self.session_interface.get_iss(state)

    def pick_config(self, issuer):
        try:
            return self.client_configs[issuer]
        except KeyError:
            return self.client_configs['']

    def run(self, client, state=''):
        while client.service_context.service_index < len(SERVICE_ORDER):
            _service = SERVICE_ORDER[client.service_context.service_index]
            try:
                conf = client.service_context.config["services"][_service]
            except KeyError:
                client.service_context.service_index += 1
                continue

            _srv = self.service_factory(
                _service, ['oidc'], service_context=client.service_context,
                client_authn_factory=self.client_authn_factory,
                state_db=client.session_interface.state_db, conf=conf)

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
                                client.service_context.redirect_uris[0]
                            }
                    elif _srv.endpoint_name == 'userinfo_endpoint':
                        kwargs = {'state': state}

                try:
                    if _service == 'EndSession':
                        kwargs['state'] = client.state

                    resp = do_request(client, _srv, request_args=req_args,
                                      **kwargs)
                except Exception as err:
                    message = traceback.format_exception(*sys.exc_info())
                    logger.error(message)
                    _header = '<h2>{} ({})</h2>'.format(err,
                                                        err.__class__.__name__)
                    _body = '<br>'.join(message)
                    _error_html = '{}<p>{}</p>'.format(_header, _body)
                    return as_bytes(_error_html)

                if isinstance(resp, dict) and 'http_response' in resp:
                    return resp

                client.service_context.service_index += 1
            else:
                _info = _srv.get_request_parameters()
                return {'url': _info['url']}

        return 'OK'

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
            keyjar.import_jwks(self.keyjar.export_jwks(True, ''), '')
            keyjar.verify_ssl = self.verify_ssl
            try:
                client = self.client_cls(
                    keyjar=keyjar, state_db=self.state_db,
                    client_authn_factory=self.client_authn_factory,
                    verify_ssl=self.verify_ssl, services=_services,
                    service_factory=self.service_factory, config=_cnf)
            except Exception as err:
                logger.error('Failed initiating client: {}'.format(err))
                message = traceback.format_exception(*sys.exc_info())
                logger.error(message)
                raise

            client.service_context.base_url = self.base_url
            client.service_context.keyjar.import_jwks(
                self.keyjar.export_jwks(True, ''), '')
            self.test_id2rp[test_id] = client

        self.issuer2rp[client.service_context.issuer] = client
        client.service_context.service_index = 0
        return self.run(client)

    # noinspection PyUnusedLocal
    def phaseN(self, client, response):
        """Step 2: Once the consumer has redirected the user back to the
        callback URL you can request the access token the user has
        approved.

        :param client: Who sent the response
        :param response: The response in what ever format it was received
        """

        _service = SERVICE_ORDER[client.service_context.service_index]
        conf = client.service_context.config["services"][_service]

        _srv = self.service_factory(
            _service, ['oidc'], service_context=client.service_context,
            client_authn_factory=self.client_authn_factory,
            state_db=client.session_interface.state_db, conf=conf)

        try:
            authresp = _srv.parse_response(response, sformat='dict')
        except Exception as err:
            logger.error('Parsing authresp: {}'.format(err))
            raise
        else:
            logger.debug('Authz response: {}'.format(authresp.to_dict()))

        if 'error' in authresp:
            raise SystemError(authresp.to_dict)

        _srv.update_service_context(authresp, response['state'])
        client.service_context.service_index += 1
        #
        client.state = response['state']

        return self.run(client, state=response['state'])


def backchannel_logout(client, request='', request_args=None):
    """

    :param request: URL encoded logout request
    :return:
    """

    if request:
        req = BackChannelLogoutRequest().from_urlencoded(as_unicode(request))
    else:
        req = BackChannelLogoutRequest(**request_args)

    kwargs = {
        'aud': client.service_context.client_id,
        'iss': client.service_context.issuer,
        'keyjar': client.service_context.keyjar
    }

    try:
        req.verify(**kwargs)
    except (MessageException, ValueError, NotForMe) as err:
        raise MessageException('Bogus logout request: {}'.format(err))

    # Find the subject through 'sid' or 'sub'

    try:
        sub = req[verified_claim_name('logout_token')]['sub']
    except KeyError:
        try:
            sid = req[verified_claim_name('logout_token')]['sid']
        except KeyError:
            raise MessageException('Neither "sid" nor "sub"')
        else:
            _state = client.session_interface.get_state_by_sid(sid)
    else:
        _state = client.session_interface.get_state_by_sub(sub)

    return _state


def factory(req_name, module_dirs, **kwargs):
    return service_factory(req_name, module_dirs, **kwargs)
