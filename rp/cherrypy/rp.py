#!/usr/bin/env python3
import importlib
import logging
import os
import sys

import cherrypy
from cryptojwt.key_jar import init_key_jar
from jinja2 import Environment
from jinja2 import FileSystemLoader

from oidcrplibtest import RPHandler
from oidcrplibtest import RT
from oidcrplibtest import get_clients

logger = logging.getLogger("")
LOGFILE_NAME = 'rp.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)


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


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-t', dest='tls', action='store_true')
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument('-m', dest='mti', action='store_true')
    parser.add_argument('-p', dest='profile')
    parser.add_argument(dest="config")
    args = parser.parse_args()

    folder = os.path.abspath(os.curdir)
    sys.path.insert(0, ".")
    config = importlib.import_module(args.config)
    try:
        _port = config.PORT
    except AttributeError:
        if args.tls:
            _port = 443
        else:
            _port = 80

    cherrypy.config.update(
        {
            'environment': 'production',
            'log.error_file': 'error.log',
            'log.access_file': 'access.log',
            'tools.trailing_slash.on': False,
            'server.socket_host': '0.0.0.0',
            'log.screen': True,
            'tools.sessions.on': True,
            'tools.encode.on': True,
            'tools.encode.encoding': 'utf-8',
            'server.socket_port': _port
        })

    provider_config = {
        '/': {
            'root_path': 'localhost',
            'log.screen': True
        },
        '/static': {
            'tools.staticdir.dir': os.path.join(folder, 'static'),
            'tools.staticdir.debug': True,
            'tools.staticdir.on': True,
            'tools.staticdir.content_types': {
                'json': 'application/json',
                'jwks': 'application/json',
                'jose': 'application/jose'
            },
            'log.screen': True,
            'cors.expose_public.on': True
        }
    }

    cprp = importlib.import_module('cprp')

    _base_url = config.BASEURL

    keyjar = init_key_jar(private_path=config.PRIVATE_JWKS_PATH,
                         key_defs=config.KEYDEFS,
                         public_path=config.PUBLIC_JWKS_PATH,
                         read_only=False)

    if args.mti:
        profile_file = 'mti.json'
    else:
        profile_file = 'full.json'

    # The client configurations are built dynamically based on the test
    # descriptions.
    clients = get_clients(args.profile, RT[args.profile], config.TESTTOOL_URL,
                          config.BASEURL, profile_file)

    template_dir = config.TEMPLATE_DIR
    jinja_env = Environment(loader=FileSystemLoader(template_dir))
    template_handler = Jinja2TemplateHandler(jinja_env)

    jwks_uri = '{}/{}'.format(_base_url, config.PUBLIC_JWKS_PATH)
    rph = RPHandler(base_url=_base_url, hash_seed="BabyHoldOn", keyjar=keyjar,
                    jwks_path=config.PRIVATE_JWKS_PATH, jwks_uri=jwks_uri,
                    client_configs=clients, services=config.SERVICES)

    cherrypy.tree.mount(cprp.Consumer(rph, 'html',
                                      template_handler=template_handler),
                        '/', provider_config)

    # If HTTPS
    if args.tls:
        cherrypy.server.ssl_certificate = config.SERVER_CERT
        cherrypy.server.ssl_private_key = config.SERVER_KEY
        if config.CA_BUNDLE:
            cherrypy.server.ssl_certificate_chain = config.CA_BUNDLE

    cherrypy.engine.start()
    cherrypy.engine.block()
