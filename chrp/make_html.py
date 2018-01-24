import conf

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

_ids = list(conf.CLIENTS.keys())
_ids.sort()

for _id in _ids:
    _part.append(pattern.format(_id, _id))

_part.append(_post_html)

print("\n".join(_part))