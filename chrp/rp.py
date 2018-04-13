#!/usr/bin/env python3
import importlib
import json
import logging
import os
import sys
from urllib.parse import urlparse

import cherrypy
from oidcmsg.key_jar import build_keyjar
from oidcmsg.key_jar import KeyJar

from oidcrplibtest import RPHandler, get_clients

logger = logging.getLogger("")
LOGFILE_NAME = 'farp.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

SIGKEY_NAME = 'sigkey.jwks'


def get_jwks(private_path, keydefs, public_path):
    if os.path.isfile(private_path):
        priv_jwks = open(private_path, 'r').read()
    else:
        _kj = build_keyjar(keydefs)[1]

        priv_jwks = _kj.export_jwks(private=True)  # private part
        head, tail = os.path.split(private_path)
        if not os.path.isdir(head):
            os.makedirs(head)
        fp = open(private_path, 'w')
        fp.write(json.dumps(priv_jwks))
        fp.close()

        pub_jwks = _kj.export_jwks()  # public part
        head, tail = os.path.split(public_path)
        if not os.path.isdir(head):
            os.makedirs(head)
        fp = open(public_path, 'w')
        fp.write(json.dumps(pub_jwks))
        fp.close()

    return priv_jwks


def get_keyjar(private_path, keydefs, public_path):
    _jwks = get_jwks(private_path, keydefs, public_path)
    return KeyJar().import_jwks(_jwks, '')


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-t', dest='tls', action='store_true')
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument('-r', dest='return_type')
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
        {'environment': 'production',
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

    _jwks = get_jwks(config.PRIVATE_JWKS_PATH, config.KEYDEFS,
                     config.PUBLIC_JWKS_PATH)

    clients = get_clients(args.return_type, config.TESTTOOL_URL,
                          config.BASEURL)

    jwks_uri = '{}/{}'.format(_base_url, config.PUBLIC_JWKS_PATH)
    rph = RPHandler(base_url=_base_url, hash_seed="BabyHoldOn", jwks=_jwks,
                    jwks_path=config.PRIVATE_JWKS_PATH, jwks_uri=jwks_uri,
                    client_configs=clients, services=config.SERVICES)

    cherrypy.tree.mount(cprp.Consumer(rph, 'html'), '/', provider_config)

    # If HTTPS
    if args.tls:
        cherrypy.server.ssl_certificate = config.SERVER_CERT
        cherrypy.server.ssl_private_key = config.SERVER_KEY
        if config.CA_BUNDLE:
            cherrypy.server.ssl_certificate_chain = config.CA_BUNDLE

    cherrypy.engine.start()
    cherrypy.engine.block()
