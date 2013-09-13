import re
import time
from collections import defaultdict

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


top_timeout_id = 0
cancelled_timeouts = set()
timeout_ids = set()
timeouts = defaultdict(list)


def set_timeout(func, timeout, *args, **kwargs):
    global top_timeout_id
    timeout_id = top_timeout_id
    top_timeout_id += 1
    if top_timeout_id > 100000:
        top_timeout_id = 0

    def timeout_func():
        timeout_ids.discard(timeout_id)
        if timeout_id in cancelled_timeouts:
            cancelled_timeouts.remove(timeout_id)
            return
        func(*args, **kwargs)

    then = time.time() + (timeout / 1000.0)
    timeouts[then].append(timeout_func)
    timeout_ids.add(timeout_id)
    return timeout_id


def cancel_timeout(timeout_id):
    if timeout_id in timeout_ids:
        cancelled_timeouts.add(timeout_id)


def call_timeouts():
    now = time.time()
    to_remove = []
    for t, tos in timeouts.items():
        if now >= t:
            for timeout in tos:
                timeout()
            to_remove.append(t)
    for k in to_remove:
        del timeouts[k]


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
