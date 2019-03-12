import os

from cryptojwt.key_jar import init_key_jar
from flask.app import Flask
from jinja2 import Environment
from jinja2 import FileSystemLoader
from oidcservice import rndstr

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
    _base_url = app.config.get('BASEURL')

    keyjar = init_key_jar(private_path=app.config.get('PRIVATE_JWKS_PATH'),
                         key_defs=app.config.get('KEYDEFS'),
                         public_path=app.config.get('PUBLIC_JWKS_PATH'),
                         read_only=False)

    if args.mti:
        profile_file = 'mti.json'
    else:
        profile_file = 'full.json'

    # The client configurations are built dynamically based on the test
    # descriptions.
    clients = get_clients(args.profile, RT[args.profile],
                          app.config.get('TESTTOOL_URL'),
                          app.config.get('BASEURL'), profile_file)

    jwks_uri = '{}/{}'.format(_base_url, app.config.get('PUBLIC_JWKS_PATH'))

    rph = RPHandler(base_url=_base_url, hash_seed="BabyHoldOn", keyjar=keyjar,
                    jwks_path=app.config.get('PRIVATE_JWKS_PATH'),
                    jwks_uri=jwks_uri,
                    client_configs=clients, services=app.config.get('SERVICES'))


    return rph


def oidc_provider_init_app(config_file, name=None, args=None, **kwargs):
    name = name or __name__
    app = Flask(name, static_url_path='', **kwargs)
    app.config.from_pyfile(os.path.join(dir_path, config_file))

    app.users = {'test_user': {'name': 'Testing Name'}}

    try:
        from .views import oidc_rp_views
    except ImportError:
        from views import oidc_rp_views

    app.register_blueprint(oidc_rp_views)
    app.secret_key = rndstr(32)

    template_dir = app.config.get('TEMPLATE_DIR')
    jinja_env = Environment(loader=FileSystemLoader(template_dir))
    app.template_handler = Jinja2TemplateHandler(jinja_env)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.rph = init_oidc_rp_handler(app, args)

    return app