#!/usr/bin/env python3
import argparse
import importlib
import os
import sys

parser = argparse.ArgumentParser()
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

_ids = list(config.CLIENTS.keys())
_ids.sort()

for _id in _ids:
    if config.CLIENTS[_id]:
        _part.append(pattern.format(_id, _id))

_part.append(_post_html)

print("\n".join(_part))