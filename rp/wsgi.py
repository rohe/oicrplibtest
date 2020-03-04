#!/usr/bin/env python3

import logging
import os

try:
    from . import application
except ImportError:
    import application

logger = logging.getLogger("")
LOGFILE_NAME = 'flrp.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

dir_path = os.path.dirname(os.path.realpath(__file__))

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-t', dest='tls', action='store_true')
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument('-m', dest='mti', action='store_true')
    parser.add_argument('-p', dest='profile')
    parser.add_argument(dest="config")
    args = parser.parse_args()

    folder = os.path.abspath(os.curdir)
    # sys.path.insert(0, ".")
    # config = importlib.import_module(args.config)

    name = 'oidc_rp'
    app = application.oidc_provider_init_app(args.config, name, args)
    web_conf = app.rp_config.web_conf
    app.run(host=web_conf["domain"], port=web_conf["port"],
            debug=web_conf.get("debug", False),
            ssl_context=('{}/{}'.format(dir_path, web_conf["server_cert"]),
                         '{}/{}'.format(dir_path, web_conf["server_key"]))
            )
