#!/usr/bin/env python3
import argparse
import importlib
import os
import sys
import json
from urllib.parse import urlparse

from oidcrplibtest import get_clients

parser = argparse.ArgumentParser()
parser.add_argument('-r', dest='return_type')
parser.add_argument(dest="config")
args = parser.parse_args()

folder = os.path.abspath(os.curdir)
sys.path.insert(0, ".")
config = importlib.import_module(args.config)


_pre_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>RP lib test</title>
</head>
<body>
  <ol>"""

pattern = """<li>
    <a href="https://0.0.0.0:8089/{}">{}</a>
</li>"""

_post_html = """  </ol>
</body>
</html>
"""

_part = [_pre_html]

clients = get_clients(args.return_type, config.TESTTOOL_URL,
                      config.BASEURL)

_ids = list(clients.keys())
_ids.sort()

for _id in _ids:
    if clients[_id]:
        _part.append(pattern.format(_id, _id))

_part.append(_post_html)

print("\n".join(_part))