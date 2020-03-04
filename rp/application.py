import os
import re

from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar
from flask.app import Flask
from jinja2 import Environment
from jinja2 import FileSystemLoader
from oidcservice import rndstr

from oidcrplibtest import Configuration
from oidcrplibtest import RPHandler
from oidcrplibtest import RT
from oidcrplibtest import get_clients

dir_path = os.path.dirname(os.path.realpath(__file__))


class TemplateHandler(object):
    def __init__(self):
        pass

    def render(self, template, **kwargs):
        raise NotImplemented()


class Jinja2TemplateHandler(TemplateHandler):
    def __init__(self, template_env):
        TemplateHandler.__init__(self)
        self.template_env = template_env

    def render(self, template, **kwargs):
        template = self.template_env.get_template(template)

        return template.render(**kwargs)


def init_oidc_rp_handler(app, args):
    _rp_conf = app.rp_config

    if _rp_conf.rp_keys:
        _kj = init_key_jar(**_rp_conf.rp_keys)
        _path = _rp_conf.rp_keys['public_path']
        # removes ./ and / from the begin of the string
        _path = re.sub('^(.)/', '', _path)
    else:
        _kj = KeyJar()
        _path = ''
    _kj.httpc_params = _rp_conf.httpc_params

    if args.mti:
        profile_file = 'mti.json'
    else:
        profile_file = 'full.json'

    # The client configurations are built dynamically based on the test
    # descriptions.
    clients = get_clients(args.profile, RT[args.profile],
                          _rp_conf.testtool_url, _rp_conf.base_url, profile_file)

    rph = RPHandler(base_url=_rp_conf.base_url, hash_seed=_rp_conf.hash_seed,
                    keyjar=_kj, jwks_path=_path, httpc_params=_rp_conf.httpc_params,
                    client_configs=clients, services=_rp_conf.services)

    return rph


def oidc_provider_init_app(config_file, name=None, args=None, **kwargs):
    name = name or __name__
    app = Flask(name, static_url_path='', **kwargs)

    app.rp_config = Configuration.create_from_config_file(config_file)

    app.users = {'test_user': {'name': 'Testing Name'}}

    try:
        from .views import oidc_rp_views
    except ImportError:
        from views import oidc_rp_views

    app.register_blueprint(oidc_rp_views)
    app.secret_key = rndstr(32)

    template_dir = app.rp_config.template_dir
    jinja_env = Environment(loader=FileSystemLoader(template_dir))
    app.template_handler = Jinja2TemplateHandler(jinja_env)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.rph = init_oidc_rp_handler(app, args)

    return app
