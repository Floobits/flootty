#!/usr/bin/env python
# coding: utf-8
try:
    unicode()
except NameError:
    unicode = str

# Heavily influenced by the work of Joshua D. Bartlett
# see: http://sqizit.bartletts.id.au/2011/02/14/pseudo-terminals-in-python/
# original copyright
# Copyright (c) 2011 Joshua D. Bartlett
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import atexit
import fcntl
import json
import optparse
import array
import os
import pty
import select
import socket
import ssl
import sys
import tempfile
import termios
import tty
import signal
import time
import base64
import collections

# boilerplate to allow running as script directly
if __name__ == "__main__" and __package__ is None:
    # The following assumes the script is in the top level of the package
    # directory.  We use dirname() to help get the parent directory to add to
    # sys.path, so that we can import the current package.  This is necessary
    # since when invoked directly, the 'current' package is not automatically
    # imported.
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, parent_dir)
    import flootty
    assert flootty
    __package__ = str("flootty")


PY2 = sys.version_info < (3, 0)


try:
    import __builtin__
    input = getattr(__builtin__, 'raw_input')
except (ImportError, AttributeError):
    pass

try:
    from . import version
    from .floo.common import api, cert, shared as G, utils
    from .floo.common.exc_fmt import str_e
    assert api and G and utils and version
except (ImportError, ValueError):
    import version
    from floo.common import api, cert, shared as G, utils
    from floo.common.exc_fmt import str_e


PROTO_VERSION = '0.11'
G.__PLUGIN_VERSION__ = version.FLOOTTY_VERSION
INITIAL_RECONNECT_DELAY = 1000
MAX_RETRIES = 12
FD_READ_BYTES = 65536
# Seconds
SELECT_TIMEOUT = 0.1
NET_TIMEOUT = 10
MAX_BYTES_TO_BUFFER = 65536


# TODO: move me to utils or use utils and reactor in common
top_timeout_id = 0
cancelled_timeouts = set()
timeout_ids = set()
timeouts = collections.defaultdict(list)


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
    for t, tos in timeouts.copy().items():
        if now >= t:
            for timeout in tos:
                timeout()
            to_remove.append(t)
    for k in to_remove:
        del timeouts[k]


def write(fd, b):
    if (not PY2) and isinstance(b, str):
            b = b.encode('utf-8')
    elif PY2 and isinstance(b, unicode):
            b = b.encode('utf-8')
    while len(b):
        try:
            n = os.write(fd, b)
            b = b[n:]
        except (IOError, OSError):
            pass


def read(fd):
    buf = b''
    while True:
        try:
            d = os.read(fd, FD_READ_BYTES)
            if not d or d == '':
                break
            buf += d
        except (IOError, OSError):
            break
    return buf


def out(*args):
    buf = "%s\r\n" % " ".join(args)
    write(pty.STDOUT_FILENO, buf)


def err(*args):
    buf = "%s\r\n" % " ".join(args)
    write(pty.STDERR_FILENO, buf)


def die(*args):
    err(*args)
    sys.exit(1)


usage = '''usage: %prog [options] [terminal_name]\n
For more help, see https://github.com/Floobits/flootty'''


def get_now_editing_workspaces():
    api_url = 'https://%s/api/workspaces/now_editing' % (G.DEFAULT_HOST)
    return api.api_request(G.DEFAULT_HOST, api_url)


def main():
    utils.reload_settings()
    default_auth = G.AUTH.get(G.DEFAULT_HOST, {})
    parser = optparse.OptionParser(usage=usage)

    parser.add_option("-u", "--username",
                      dest="username",
                      default=default_auth.get('username'),
                      help="Your Floobits username")

    parser.add_option("-s", "--secret",
                      dest="secret",
                      default=default_auth.get('secret'),
                      help="Your Floobits secret (api key)")

    parser.add_option("-c", "--create",
                      dest="create",
                      default=False,
                      action="store_true",
                      help="The terminal name to create")

    parser.add_option("--host",
                      dest="host",
                      default=G.DEFAULT_HOST,
                      help="The host to connect to. Deprecated. Use --url instead.")

    parser.add_option("-p", "--port",
                      dest="port",
                      default=G.DEFAULT_PORT,
                      help="The port to connect to. Deprecated. Use --url instead.")

    parser.add_option("-w", "--workspace",
                      dest="workspace",
                      help="The workspace name. --owner is required with this option. Deprecated. Use --url instead.")

    parser.add_option("-o", "--owner",
                      dest="owner",
                      help="The workspace owner. --workspace is required with this option. Deprecated. Use --url instead.")

    parser.add_option("-l", "--list",
                      dest="list",
                      default=False,
                      action="store_true",
                      help="List all terminals in the workspace")

    parser.add_option("--unsafe",
                      dest="safe",
                      default=True,
                      action="store_false",
                      help="Less safe terminal. This allows other users to send enter in your terminal.")

    parser.add_option("--no-ssl",
                      dest="use_ssl",
                      default=True,
                      action="store_false",
                      help="Do not use this option unless you know what you are doing!")

    parser.add_option("--url",
                      dest="workspace_url",
                      default=None,
                      help="The URL of the workspace to connect to.")

    parser.add_option("--resize",
                      dest="resize",
                      default=False,
                      action="store_true",
                      help="Resize your terminal to the host terminal size.")

    parser.add_option("--shell",
                      dest="shell",
                      default=os.environ.get("SHELL", None),
                      help="The shell you would like to use with flootty. Defaults to $SHELL.")

    parser.add_option("-P", "--preserve-ps1",
                      dest="set_prompt",
                      default=True,
                      action="store_false",
                      help="Don't change $PS1 (bash/zsh prompt)")

    parser.add_option("-v", "--version",
                      dest="version",
                      default=False,
                      action="store_true",
                      help="Print version")

    options, args = parser.parse_args()

    if options.version:
        print('flootty %s' % version.FLOOTTY_VERSION)
        return

    default_term_name = ""
    if options.create:
        default_term_name = "ftty"

    term_name = args and args[0] or default_term_name

    if options.workspace and options.owner and options.workspace_url:
        # TODO: confusing
        parser.error("You can either specify --workspace and --owner, or --url, but not both.")

    if bool(options.workspace) != bool(options.owner):
        parser.error("You must specify a workspace and owner or neither.")

    for opt in ['owner', 'workspace']:
        if getattr(options, opt):
            print('%s is deprecated. Please use --url instead.' % opt)

    if not options.workspace or not options.owner:
        floo = {}
        if options.workspace_url:
            floo = utils.parse_url(options.workspace_url)
        else:
            for floo_path in walk_up(os.path.realpath('.')):
                try:
                    floo = json.loads(open(os.path.join(floo_path, '.floo'), 'rb').read().decode('utf-8'))
                    floo = utils.parse_url(floo['url'])
                except Exception:
                    pass
                else:
                    break
        options.host = floo.get('host')
        options.workspace = floo.get('workspace')
        options.owner = floo.get('owner')
        options.use_ssl = floo.get('secure')
        if not options.port:
            options.port = floo.get('port')
        if not options.host:
            options.host = floo.get('host')

    if options.host is None:
        options.host = G.DEFAULT_HOST

    if options.host != G.DEFAULT_HOST and options.secret == default_auth.get('secret'):
        auth = G.AUTH.get(options.host)
        if not auth:
            return die("Please add credentials for %s in ~/.floorc.json" % options.host)
        options.username = auth.get('username')
        options.secret = auth.get('secret')

    if not options.workspace or not options.owner:
        try:
            now_editing = get_now_editing_workspaces()
        except Exception as e:
            print(str_e(e))
        else:
            if len(now_editing.body) == 1:
                options.workspace = now_editing.body[0]['name']
                options.owner = now_editing.body[0]['owner']
        # TODO: list possible workspaces to join if > 1 is active

    if options.list:
        if len(term_name) != 0:
            die("I don't understand why you gave me a positional argument.")

    for opt in ['username', 'secret']:
        if not getattr(options, opt):
            parser.error('%s not given. Please use --%s or add credentials to ~/.floorc.json' % (opt, opt))

    for opt in ['workspace', 'owner']:
        if not getattr(options, opt):
            parser.error('%s not given' % opt)

    color_reset = '\033[0m'
    if not G.FLOOTTY_SAFE:
        options.safe = G.FLOOTTY_SAFE
    if options.safe:
        green = '\033[92m'
        print('%sTerminal is safe. Other users will not be able to send [enter]%s' % (green, color_reset))
    else:
        yellorange = '\033[93m'
        print('%sTerminal is unsafe. Other users will be able to send [enter]. Be wary!%s' % (yellorange, color_reset))

    f = Flootty(options, term_name)
    G.AGENT = f
    atexit.register(f.cleanup)
    f.connect_to_internet()
    f.select()


def walk_up(path):
    def step_up(p):
        return os.path.realpath(os.path.join(p, '..'))
    parent = step_up(path)
    while parent != path:
        yield path
        path = parent
        parent = step_up(path)
    yield path


class FD(object):
    def __init__(self, fileno, reader=None, writer=None, errer=None, name=None):
        self.fileno = fileno
        self.reader = reader
        self.writer = writer
        self.errer = errer
        self.name = name

    def __getitem__(self, key):
        return getattr(self, key, None)

    def __str__(self):
        return str(self.name)


class Flootty(object):
    '''Mostly OK at sharing a shell'''

    def __init__(self, options, term_name):
        self.master_fd = None
        self.original_wincher = None
        self.fds = {}
        self.readers = set()
        self.writers = set()
        self.errers = set()
        self.empty_selects = 0
        self.reconnect_timeout = None

        self.buf_out = collections.deque()
        self.buf_in = b''

        self.host = options.host
        self.port = int(options.port)
        self.workspace = options.workspace
        self.owner = options.owner
        self.username = options.username
        self.options = options
        self.term_name = term_name

        self.authed = False
        self.term_id = None
        self.orig_stdin_atts = None
        self.orig_stdout_atts = None
        self.last_stdin = 0
        self.reconnect_delay = INITIAL_RECONNECT_DELAY
        self._retries = MAX_RETRIES

    def add_fd(self, fileno, **kwargs):
        try:
            fileno = fileno.fileno()
        except:
            fileno = fileno
        fd = FD(fileno, **kwargs)

        self.fds[fileno] = fd
        if fd.reader:
            self.readers.add(fileno)
        if fd.writer:
            self.writers.add(fileno)
        if fd.errer:
            self.errers.add(fileno)

    def remove_fd(self, fileno):
        self.readers.discard(fileno)
        self.writers.discard(fileno)
        self.errers.discard(fileno)
        try:
            del self.fds[fileno]
        except KeyError:
            pass

    def transport(self, name, data):
        data['name'] = name
        self.buf_out.append(data)

    def select(self):
        '''
        '''
        attrs = ('errer', 'reader', 'writer')

        while True:
            call_timeouts()

            if len(self.buf_out) == 0 and self.sock:
                self.writers.remove(self.sock.fileno())
            try:
                # NOTE: you will never have to write anything without reading first from a different one
                _in, _out, _except = select.select(self.readers, self.writers, self.errers, SELECT_TIMEOUT)
            except (IOError, OSError) as e:
                continue
            except (select.error, socket.error, Exception) as e:
                # Interrupted system call.
                if e[0] == 4:
                    continue
                self.reconnect()
                continue
            finally:
                if self.sock:
                    self.writers.add(self.sock.fileno())

            for position, fds in enumerate([_except, _in, _out]):
                attr = attrs[position]
                for fd in fds:
                    # the handler can remove itself from self.fds...
                    handler = self.fds.get(fd)
                    if handler is None:
                        continue
                    handler = handler[attr]
                    if handler:
                        handler(fd)
                    else:
                        raise Exception('no handler for fd: %s %s' % (fd, attr))

    def cloud_read(self, fd):
        buf = b''
        try:
            while True:
                d = self.sock.recv(FD_READ_BYTES)
                if not d:
                    break
                buf += d
        except (socket.error, TypeError):
            pass
        if buf:
            self.empty_selects = 0
            self.handle(buf)
        else:
            self.empty_selects += 1
            if (int(self.empty_selects * SELECT_TIMEOUT)) > NET_TIMEOUT:
                err('No data from sock.recv() {0} times.'.format(self.empty_selects))
                return self.reconnect()

    def cloud_write(self, fd):
        new_buf_out = collections.deque()
        try:
            while True:
                item = self.buf_out.popleft()
                data = json.dumps(item) + '\n'
                if self.authed or item['name'] == 'auth':
                    if not PY2:
                        data = data.encode('utf-8')
                    self.sock.sendall(data)
                else:
                    new_buf_out.append(item)
        except socket.error:
            self.buf_out.appendleft(item)
            self.reconnect()
        except IndexError:
            pass
        self.buf_out.extendleft(new_buf_out)

    def cloud_err(self, err):
        out('reconnecting because of %s' % err)
        self.reconnect()

    def handle(self, req):
        self.buf_in += req
        while True:
            before, sep, after = self.buf_in.partition(b'\n')
            if not sep:
                break
            data = json.loads(before.decode('utf-8'), encoding='utf-8')
            self.handle_event(data)
            self.buf_in = after

    def handle_event(self, data):
        name = data.get('name')
        if not name:
            return out('no name in data?!?')
        func = getattr(self, "on_%s" % (name), None)
        if not func:
            return
        func(data)

    def on_room_info(self, ri):
        self.authed = True
        self.ri = ri
        self._retries = MAX_RETRIES

        def list_terms(terms):
            term_name = ""
            for term_id, term in terms.items():
                owner = str(term['owner'])
                term_name = term['term_name']
                out('terminal %s created by %s' % (term['term_name'], ri['users'][owner]['username']))
            return term_name

        if self.options.create:
            buf = self._get_pty_size()
            term_name = self.term_name
            i = 0
            term_names = [term['term_name'] for term_id, term in ri['terms'].items()]
            while term_name in term_names:
                i += 1
                term_name = self.term_name + str(i)
            self.term_name = term_name
            return self.transport('create_term', {'term_name': self.term_name, 'size': [buf[1], buf[0]]})
        elif self.options.list:
            out('Terminals in %s::%s' % (self.owner, self.workspace))
            list_terms(ri['terms'])
            return die()
        elif not self.term_name:
            if len(ri['terms']) == 0:
                out('There is no active terminal in this workspace. Do you want to share your terminal? (y/n)')
                choice = input().lower()
                self.term_name = "_"
                if choice == 'y':
                    self.options.create = True
                    buf = self._get_pty_size()
                    return self.transport('create_term', {'term_name': self.term_name, 'size': [buf[1], buf[0]]})
                else:
                    die('If you ever change your mind, you can share your terminal using the --create [super_awesome_name] flag.')
            elif len(ri['terms']) == 1:
                term_id, term = list(ri['terms'].items())[0]
                self.term_id = int(term_id)
                self.term_name = term['term_name']
            else:
                out('More than one active term exists in this workspace.')
                example_name = list_terms(ri['terms'])
                die('Please pick a workspace like so: flootty %s' % example_name)
        else:
            for term_id, term in ri['terms'].items():
                if term['term_name'] == self.term_name:
                    self.term_id = int(term_id)
                    break

        if self.term_id is None:
            die('No terminal with name %s' % self.term_name)
        return self.join_term()

    def on_ping(self, data):
        self.transport('pong', {})

    def on_disconnect(self, data):
        reason = data.get('reason')
        out('Disconnected by server!')
        if reason:
            # TODO: don't kill terminal until current process is done or something
            die('Reason: %s' % reason)
        self.reconnect()

    def on_error(self, data):
        if self.term_id is None:
            die(data.get('msg'))
        else:
            out('Error from server: %s' % data.get('msg'))

    def on_create_term(self, data):
        if data.get('term_name') != self.term_name:
            return
        self.term_id = int(data.get('id'))
        self.create_term()

    def on_delete_term(self, data):
        term_id = int(data.get('id'))
        if term_id != self.term_id:
            return
        die('User %s killed the terminal. Exiting.' % (data.get('username')))

    def on_update_term(self, data):
        term_id = int(data.get('id'))
        if term_id != self.term_id:
            return
        self._set_pty_size()

    def on_term_stdin(self, data):
        term_id = int(data.get('id'))
        if term_id != self.term_id:
            return
        if not self.options.create:
            return
        self.handle_stdio(base64.b64decode(data['data']), data.get('user_id'))

    def on_term_stdout(self, data):
        term_id = int(data.get('id'))
        if term_id != self.term_id:
            return
        self.handle_stdio(data['data'])

    def reconnect(self):
        if self.reconnect_timeout:
            return

        new_buf_out = collections.deque()
        total_len = 0
        while True:
            try:
                item = self.buf_out.popleft()
            except IndexError:
                break

            if item['name'] == 'term_stdout':
                total_len += len(item['data'])
                if total_len > MAX_BYTES_TO_BUFFER:
                    continue
                new_buf_out.appendleft(item)

        self.buf_out = new_buf_out

        if self.sock:
            self.remove_fd(self.sock.fileno())
            try:
                self.sock.shutdown(2)
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        self.authed = False
        self.reconnect_delay *= 1.5
        if self.reconnect_delay > 10000:
            self.reconnect_delay = 10000
        if self.host == 'floobits.com':
            # Only use proxy.floobits.com if we're trying to connect to floobits.com
            G.OUTBOUND_FILTERING = self._retries % 4 == 0
        self._retries -= 1
        if self._retries == 0:
            out('Floobits Error! Too many reconnect failures. Giving up.')
        self.reconnect_timeout = set_timeout(self.connect_to_internet, self.reconnect_delay)

    def send_auth(self):
        self.buf_out.appendleft({
            'name': 'auth',
            'username': self.options.username,
            'secret': self.options.secret,
            'room': self.workspace,
            'room_owner': self.owner,
            'client': 'flootty %s' % version.FLOOTTY_VERSION,
            'platform': sys.platform,
            'version': PROTO_VERSION
        })

    def connect_to_internet(self):
        self.empty_selects = 0
        self.reconnect_timeout = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.options.use_ssl:
            self.cert_fd = tempfile.NamedTemporaryFile()
            self.cert_fd.write(cert.CA_CERT.encode('utf-8'))
            self.cert_fd.flush()
            self.sock = ssl.wrap_socket(self.sock, ca_certs=self.cert_fd.name, cert_reqs=ssl.CERT_REQUIRED)
        elif self.port == 3448:
            self.port = 3148
        out('Connecting to %s' % self.workspace_url())

        if G.OUTBOUND_FILTERING:
            host = G.OUTBOUND_FILTER_PROXY_HOST
            port = G.OUTBOUND_FILTER_PROXY_PORT
        else:
            host = self.host
            port = self.port

        try:
            self.sock.connect((host, port))
            if self.options.use_ssl:
                self.sock.do_handshake()
        except socket.error as e:
            out('Error connecting: %s.' % e)
            return self.reconnect()
        self.sock.setblocking(0)
        out('Connected!')
        self.send_auth()
        self.add_fd(self.sock, reader=self.cloud_read, writer=self.cloud_write, errer=self.cloud_err, name='net')
        self.reconnect_delay = INITIAL_RECONNECT_DELAY

    def workspace_url(self):
        proto = {True: "https", False: "http"}
        proto_str = proto[self.options.use_ssl]
        port_str = ''
        if self.options.use_ssl:
            if self.port != 3448:
                port_str = ':%s' % self.port
        else:
            if self.port != 3148:
                port_str = ':%s' % self.port
        return '%s://%s%s/%s/%s' % (proto_str, self.host, port_str, self.owner, self.workspace)

    def join_term(self):
        out('Successfully joined %s' % (self.workspace_url()))
        self.orig_stdout_atts = tty.tcgetattr(sys.stdout)
        stdout = sys.stdout.fileno()
        tty.setraw(stdout)
        fl = fcntl.fcntl(stdout, fcntl.F_GETFL)
        fcntl.fcntl(stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        self.orig_stdin_atts = tty.tcgetattr(sys.stdin)
        stdin = sys.stdin.fileno()
        tty.setraw(stdin)
        fl = fcntl.fcntl(stdin, fcntl.F_GETFL)
        fcntl.fcntl(stdin, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        def ship_stdin(fd):
            data = read(fd)
            if data:
                self.transport("term_stdin", {'data': base64.b64encode(data).decode('utf8'), 'id': self.term_id})

        if 'term_stdin' in self.ri['perms']:
            out('You have permission to write to this terminal. Remember: With great power comes great responsibility.')
            self.add_fd(stdin, reader=ship_stdin, name='join_term_stdin')
        else:
            out('You do not have permission to write to this terminal.')

        def stdout_write(buf):
            write(stdout, base64.b64decode(buf))

        self.handle_stdio = stdout_write
        self._set_pty_size(self.ri['terms'][str(self.term_id)]['size'])

    def create_term(self):
        '''
        Create a spawned process.
        Based on the code for pty.spawn().
        '''

        if self.master_fd:
            # reconnected. don't spawn a new shell
            out('Reconnected to %s' % (self.workspace_url()))
            return
        shell = self.options.shell
        if shell is None:
            default_shell = '/bin/sh'
            out('SHELL not set as an enviornment variable, unable to determine your default shell, using %s' % default_shell)
            shell = default_shell
        out('Successfully joined %s' % (self.workspace_url()))

        self.child_pid, self.master_fd = pty.fork()
        if self.child_pid == pty.CHILD:
            os.execlpe(shell, shell, '--login', os.environ)

        self.orig_stdin_atts = tty.tcgetattr(sys.stdin.fileno())
        tty.setraw(pty.STDIN_FILENO)
        self.original_wincher = signal.signal(signal.SIGWINCH, self._signal_winch)
        self._set_pty_size()

        def slave_death(fd):
            die('Exiting flootty because child exited.')

        self.extra_data = b''

        def stdout_write(fd):
            '''
            Called when there is data to be sent from the child process back to the user.
            '''
            try:
                data = self.extra_data + os.read(fd, FD_READ_BYTES)
            except:
                data = None
            if not data:
                return die("Time to go!")

            self.transport("term_stdout", {'data': base64.b64encode(data).decode('utf8'), 'id': self.term_id})
            write(pty.STDOUT_FILENO, data)

        self.add_fd(self.master_fd, reader=stdout_write, errer=slave_death, name='create_term_stdout_write')

        def stdin_write(fd):
            data = os.read(fd, FD_READ_BYTES)
            if data:
                write(self.master_fd, data)

                now = time.time()
                # Only send stdin event if it's been > 2 seconds. This prevents people from figuring out password lengths
                if now - self.last_stdin > 2:
                    self.transport("term_stdin", {'data': ' ', 'id': self.term_id})
                    self.last_stdin = now

        self.add_fd(pty.STDIN_FILENO, reader=stdin_write, name='create_term_stdin_write')

        def net_stdin_write(buf, user_id=None):
            # Lame work-around to get this working in python 2 and 3
            a = '\a'.encode('utf-8')
            n = '\n'.encode('utf-8')
            r = '\r'.encode('utf-8')
            eof = '\004'.encode('utf-8')
            empty = ''.encode('utf-8')
            if self.options.safe:
                # Stop people from using ctrl+d to end sessions
                if buf.find(eof) != -1:
                    buf = buf.replace(eof, empty)
                if buf.find(n) != -1 or buf.find(r) != -1:
                    to = user_id or []
                    self.transport('datamsg', {
                        'to': to,
                        'data': {
                            'name': 'safe_term',
                            'term_id': self.term_id,
                            'msg': 'Terminal %s is in safe mode. Other users are not allowed to press enter.' % self.term_name,
                        }})
                    self.transport('term_stdout', {
                        'id': self.term_id,
                        'data': base64.b64encode(a).decode('utf-8'),
                    })
                    buf = buf.replace(n, empty)
                    buf = buf.replace(r, empty)
                if not buf:
                    return
            write(self.master_fd, buf)

        self.handle_stdio = net_stdin_write
        color_green = '\\[\\e[32m\\]'
        color_reset = '\\[\\033[0m\\]'
        color_yellorange = '\\[\\e[93m\\]'

        # TODO: other shells probably use weird color escapes
        if 'zsh' in shell:
            color_green = "%{%F{green}%}"
            color_reset = "%{%f%}"
            color_yellorange = "%{%F{yellow}%}"

        if self.options.set_prompt:
            term_color = color_yellorange
            if self.options.safe:
                term_color = color_green
            # Not confusing at all </sarcasm>
            cmd = 'PS1="%s%s::%s::%s%s%s%s $PS1"\n' % (color_green, self.owner, self.workspace, color_reset, term_color, self.term_name, color_reset)
            if 'fish' in shell:
                out('Unable to set prompt for your shell. Do not forget that you are sharing this terminal!')
            else:
                write(self.master_fd, cmd)

    def _signal_winch(self, signum, frame):
        '''
        Signal handler for SIGWINCH - window size has changed.
        '''
        self._set_pty_size()

    def _get_pty_size(self):
        buf = array.array('h', [0, 0, 0, 0])
        fcntl.ioctl(pty.STDOUT_FILENO, termios.TIOCGWINSZ, buf, True)
        return buf

    def _set_pty_size(self, size=None):
        '''
        Sets the window size of the child pty based on the window size of our own controlling terminal.
        '''
        # Get the terminal size of the real terminal, set it on the pseudoterminal.
        buf = self._get_pty_size()
        if size:
            buf[0] = size[1]
            buf[1] = size[0]

        if self.options.create:
            assert self.master_fd is not None
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, buf)
            if self.term_id:
                self.transport('update_term', {'id': self.term_id, 'size': [buf[1], buf[0]]})
        else:
            # XXXX: this resizes the window :/
            if self.options.resize:
                os.write(pty.STDOUT_FILENO, "\x1b[8;{rows};{cols}t".format(rows=buf[0], cols=buf[1]))
            fcntl.ioctl(pty.STDOUT_FILENO, termios.TIOCSWINSZ, buf)

    def cleanup(self):
        if self.orig_stdout_atts:
            self.orig_stdout_atts[3] = self.orig_stdout_atts[3] | termios.ECHO
            tty.tcsetattr(sys.stdout, tty.TCSAFLUSH, self.orig_stdout_atts)
        if self.orig_stdin_atts:
            self.orig_stdin_atts[3] = self.orig_stdin_atts[3] | termios.ECHO
            tty.tcsetattr(sys.stdin, tty.TCSAFLUSH, self.orig_stdin_atts)
        if self.original_wincher:
            signal.signal(signal.SIGWINCH, self.original_wincher)
        try:
            self.cert_fd.close()
        except Exception:
            pass
        print('ciao.')

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        err(str_e(e))
        api.send_error(None, e)
