#!/usr/bin/env python

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

import array
import atexit
import fcntl
import json
import optparse
import os
import pty
import select
import signal
import socket
import ssl
import sys
import termios
import tty

try:
    import queue
    assert queue
except ImportError:
    import Queue as queue

CERT = os.path.join(os.getcwd(), 'startssl-ca.pem')

PROTO_VERSION = '0.02'
CLIENT = 'flootty'

# The following escape codes are xterm codes.
# See http://rtfm.etla.org/xterm/ctlseq.html for more.
START_ALTERNATE_MODE = set('\x1b[?{0}h'.format(i) for i in ('1049', '47', '1047'))
END_ALTERNATE_MODE = set('\x1b[?{0}l'.format(i) for i in ('1049', '47', '1047'))
ALTERNATE_MODE_FLAGS = tuple(START_ALTERNATE_MODE) + tuple(END_ALTERNATE_MODE)

INITIAL_RECONNECT_DELAY = 1000


def read_floorc():
    settings = {}
    p = os.path.expanduser('~/.floorc')
    try:
        fd = open(p, 'rb')
    except IOError as e:
        if e.errno == 2:
            return settings
        raise
    data = fd.read()
    fd.close()
    for line in data.split('\n'):
        position = line.find(' ')
        if position < 0:
            continue
        settings[line[:position]] = line[position + 1:]
    return settings


def out(*args):
    os.write(pty.STDOUT_FILENO, " ".join(args))


def err(*args):
    os.write(pty.STDERR_FILENO, " ".join(args))


def findlast(s, substrs):
    '''
    Finds whichever of the given substrings occurs last in the given string and returns that substring, or returns None if no such strings occur.
    '''
    i = -1
    result = None
    for substr in substrs:
        pos = s.rfind(substr)
        if pos > i:
            i = pos
            result = substr
    return result


def main():
    settings = read_floorc()
    parser = optparse.OptionParser()

    parser.add_option("--user",
        dest="user",
        default=settings.get('username'),
        help="your username")

    parser.add_option("--secret",
        dest="secret",
        default=settings.get('secret'),
        help="your secret (apikey)")

    parser.add_option("--host",
        dest="host",
        default="localhost",
        help="the host to connect to")

    parser.add_option("--port",
        dest="port",
        default=3148,
        help="the port to connect to")

    parser.add_option("--join",
        dest="join",
        help="the terminal name to join")

    parser.add_option("--create",
        dest="create",
        help="the terminal name to create")

    parser.add_option("--room",
        dest="room",
        help="the room name")

    parser.add_option("--owner",
        dest="owner",
        help="the room owner")

    parser.add_option("--list",
        dest="list",
        help="list all ptys in the room")

    options, args = parser.parse_args()

    out('\nThe dream has begun.\n')
    f = Flooty(options)
    atexit.register(f.cleanup)
    f.startup()

    out('\nThe dream is (probably) over.\n')


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


class Flooty(object):
    '''
    '''

    def __init__(self, options):
        self.master_fd = None
        self.old_handler = None
        self.mode = None

        self.fds = {}
        self.readers = set()
        self.writers = set()
        self.errers = set()
        self.empty_selects = 0

        self.buf_out = queue.Queue()
        self.buf_in = ''

        self.host = options.host
        self.port = options.port
        self.room = options.room
        self.owner = options.owner
        self.options = options

        self.authed = False
        self.term_id = None

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

    def transport(self, name, data):
        data['name'] = name
        self.buf_out.put(data, True)

    def select(self):
        '''
        '''
        attrs = ('errer', 'reader', 'writer')

        while True:
            if self.buf_out.qsize() == 0:
                self.writers.remove(self.sock.fileno())
            try:
                # NOTE: you will never have to write anything without reading first from a different one
                _in, _out, _except = select.select(self.readers, self.writers, self.errers, 1)
            except (IOError, OSError) as e:
                continue
            except (select.error, socket.error, Exception) as e:
                # Interrupted system call.
                if e[0] == 4:
                    continue
                err('Error in select(): %s' % str(e))
                return self.reconnect()
            finally:
                self.writers.add(self.sock.fileno())

            for position, fds in enumerate([_except, _in, _out]):
                attr = attrs[position]
                for fd in fds:
                    handler = self.fds[fd][attr]
                    if handler:
                        handler(fd)
                    else:
                        raise Exception('no handler for fd: %s %s' % (fd, attr))

    def cloud_read(self, fd):
        buf = ''
        while True:
            try:
                d = self.sock.recv(4096)
                if not d:
                    break
                buf += d
            except (socket.error, TypeError):
                break
        if buf:
            self.empty_selects = 0
            self.handle(buf)
        else:
            self.empty_selects += 1
            if self.empty_selects > 10:
                err('No data from sock.recv() {0} times.'.format(self.empty_selects))
                return self.reconnect()

    def handle(self, req):
        self.buf_in += req
        while True:
            before, sep, after = self.buf_in.partition('\n')
            if not sep:
                break
            try:
                data = json.loads(before)
            except Exception as e:
                out('Unable to parse json: %s' % str(e))
                raise e
            self.handle_event(data)
            self.buf_in = after

    def handle_event(self, data):
        name = data.get('name')
        if not name:
            return out('no name in data?!?')
        func = getattr(self, "on_%s" % (name), None)
        if not func:
            #out('unknown name %s data: %s' % (name, data))
            return
        func(data)

    def on_room_info(self, ri):
        self.authed = True
        if self.options.create:
            self.transport('create_term', {'term_name': self.options.create})
            self.create_term()
        elif self.options.join:
            for term_id, term in ri['terms'].items():
                if term['name'] == self.options.join:
                    self.term_id = int(term_id)
                    break
            if self.term_id is None:
                out('No terminal with name %s' % self.options.join)
                sys.exit(1)
            self.join_term()
        elif self.options.list:
            print('Terminals in %s::%s' % (self.owner, self.room))
            for term_id, term in ri['terms'].items():
                print('terminal %s created by %s' % (term['name'], term['owner']))
            sys.exit(0)

    def on_create_term(self, data):
        self.term_id = data.get('id')

    def on_term_stdin(self, data):
        if not self.options.create:
            out('omg got a stdin event but we should never get one')
            return
        if data.get('id') != self.term_id:
            out('wrong id')
            return
        self.handle_stdio(data['data'])

    def on_term_stdout(self, data):
        if not self.options.join:
            out('omg got a stdout event but we should never get one')
            return
        if data.get('id') != self.term_id:
            out('wrong id %s vs %s' % (data.get('id'), self.term_id))
            return
        self.handle_stdio(data['data'])

    def cloud_write(self, fd):
        while True:
            try:
                item = self.buf_out.get_nowait()
            except queue.Empty:
                break
            else:
                self.sock.sendall(json.dumps(item) + '\n')

    def cloud_err(self, err):
        out('reconnecting because of %s' % err)
        self.reconnect()

    def reconnect(self):
        out('not reconnecting\n')
        sys.exit()

    def send_auth(self):
        self.buf_out = queue.Queue()
        self.transport('auth', {
            'username': self.options.user,
            'secret': self.options.secret,
            'room': self.room,
            'room_owner': self.owner,
            'client': CLIENT,
            'platform': sys.platform,
            'version': PROTO_VERSION
        })

    def connect_to_internet(self):
        self.empty_selects = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #self.sock = ssl.wrap_socket(sock, ca_certs=CERT, cert_reqs=ssl.CERT_REQUIRED)
        out('Connecting to %s:%s\n' % (self.host, self.port))
        try:
            self.sock.connect((self.host, self.port))
            #self.sock.do_handshake()
        except socket.error as e:
            out('Error connecting: %s' % e)
            self.reconnect()
        self.sock.setblocking(0)
        out('Connected!\n')
        self.send_auth()
        self.add_fd(self.sock, reader=self.cloud_read, writer=self.cloud_write, errer=self.cloud_err, name='net')
        self.reconnect_delay = INITIAL_RECONNECT_DELAY

    def startup(self):
        self.connect_to_internet()
        self.select()

    def join_term(self):
        stdout = sys.stdout.fileno()
        tty.setraw(stdout)
        fl = fcntl.fcntl(stdout, fcntl.F_GETFL)
        fcntl.fcntl(stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        stdin = sys.stdin.fileno()
        tty.setraw(stdin)
        fl = fcntl.fcntl(stdin, fcntl.F_GETFL)
        fcntl.fcntl(stdin, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        def ship_stdin(fd):
            data = os.read(fd, 1024)
            if data:
                self.transport("term_stdin", {'data': data, 'id': self.term_id})

        self.add_fd(stdin, reader=ship_stdin, name='join_term_stdin')

        def stdout_write(buf):
            while len(buf) > 0:
                try:
                    n = os.write(stdout, buf.encode('utf-8'))
                    buf = buf[n:]
                except (IOError, OSError):
                    pass

        self.handle_stdio = stdout_write

    def create_term(self):
        '''
        Create a spawned process.
        Based on the code for pty.spawn().
        '''

        assert self.master_fd is None
        shell = os.environ['SHELL']

        pid, master_fd = pty.fork()
        self.master_fd = master_fd
        if pid == pty.CHILD:
            os.execlp(shell, shell, '--login')

        self.old_handler = signal.signal(signal.SIGWINCH, self._signal_winch)
        try:
            self.mode = tty.tcgetattr(pty.STDIN_FILENO)
            tty.setraw(pty.STDIN_FILENO)
        # This is the same as termios.error
        except tty.error:
            pass

        self._set_pty_size()

        def slave_death(fd):
            out('child died probably')
            sys.exit(0)

        def stdout_write(fd):
            '''
            Called when there is data to be sent from the child process back to the user.
            '''
            data = os.read(fd, 1024)
            if data:
                self.transport("term_stdout", {'data': data, 'id': self.term_id})
                out(data)

        self.add_fd(self.master_fd, reader=stdout_write, errer=slave_death, name='create_term_stdout_write')

        def stdin_write(fd):
            data = os.read(fd, 1024)
            while data and len(data) > 0:
                try:
                    n = os.write(self.master_fd, data)
                    data = data[n:]
                except (IOError, OSError):
                    pass

        self.add_fd(pty.STDIN_FILENO, reader=stdin_write, name='create_term_stdin_write')

        def net_stdin_write(buf):
            while buf and len(buf) > 0:
                try:
                    n = os.write(self.master_fd, buf)
                    buf = buf[n:]
                except (IOError, OSError):
                    pass

        self.handle_stdio = net_stdin_write

    def cleanup(self):
        mode = getattr(self, 'mode')
        if mode:
            tty.tcsetattr(pty.STDIN_FILENO, tty.TCSAFLUSH, mode)
        if self.master_fd:
            try:
                os.close(self.master_fd)
            except Exception:
                pass
            self.master_fd = None
        if self.old_handler:
            signal.signal(signal.SIGWINCH, self.old_handler)
        sys.exit()

    def _signal_winch(self, signum, frame):
        '''
        Signal handler for SIGWINCH - window size has changed.
        '''
        self._set_pty_size()

    def _set_pty_size(self):
        '''
        Sets the window size of the child pty based on the window size of our own controlling terminal.
        '''
        assert self.master_fd is not None

        # Get the terminal size of the real terminal, set it on the pseudoterminal.
        buf = array.array('h', [0, 0, 0, 0])
        fcntl.ioctl(pty.STDOUT_FILENO, termios.TIOCGWINSZ, buf, True)
        fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, buf)


if __name__ == '__main__':
    main()
