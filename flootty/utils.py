import re

try:
    from urllib.parse import urlparse
    assert urlparse
except ImportError:
    from urlparse import urlparse

try:
    from . import shared as G
    assert G
except (ImportError, ValueError):
    import shared as G


def parse_url(workspace_url):
    secure = G.SECURE
    owner = None
    workspace_name = None
    parsed_url = urlparse(workspace_url)
    port = parsed_url.port
    if parsed_url.scheme == 'http':
        if not port:
            port = 3148
        secure = False
    else:
        if not port:
            port = G.DEFAULT_PORT
    result = re.match('^/r/([-\@\+\.\w]+)/([-\w]+)/?$', parsed_url.path)
    if result:
        (owner, workspace_name) = result.groups()
    else:
        raise ValueError('%s is not a valid Floobits URL' % workspace_url)
    return {
        'host': parsed_url.hostname,
        'owner': owner,
        'port': port,
        'workspace': workspace_name,
        'secure': secure,
    }
