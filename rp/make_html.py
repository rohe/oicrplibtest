#!/usr/bin/env python3
import argparse
import os
import sys

from oidcrplibtest import Configuration
from oidcrplibtest import RT
from oidcrplibtest import get_clients

parser = argparse.ArgumentParser()
parser.add_argument('-m', dest='mti', action='store_true')
parser.add_argument('-p', dest='profile')
parser.add_argument(dest="config")
args = parser.parse_args()

folder = os.path.abspath(os.curdir)
sys.path.insert(0, ".")
config = Configuration.create_from_config_file(args.config)

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
    <a href="{}/rp/{{}}">{{}}</a>
</li>""".format(config.base_url)

_post_html = """  </ol>
</body>
</html>
"""

_part = [_pre_html]

if args.mti:
    profile_file = 'mti.json'
else:
    profile_file = 'full.json'

clients = get_clients(args.profile, RT[args.profile], config.testtool_url,
                      config.base_url, profile_file)

_ids = list(clients.keys())
_ids.sort()

for _id in _ids:
    if clients[_id]:
        _part.append(pattern.format(_id, _id))

_part.append(_post_html)

print("\n".join(_part))
