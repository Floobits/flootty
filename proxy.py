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
import fcntl
import os
import pty
import select
import signal
import sys
import termios
import tty
import socket
#import ssl
import json
import atexit
import Queue
import optparse


CERT = os.path.join(os.getcwd(), 'startssl-ca.pem')

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
        default=settings.get('user'),
        help="your username")

    parser.add_option("--secret",
        dest="secret",
        default=settings.get('secret'),
        help="your secret (apikey)")

    parser.add_option("--join",
        dest="room",
        help="the room to join")

    parser.add_option("--list",
        dest="list",
        help="list all ptys in the room")

    parser.add_option("--create",
        dest="create",
        help="create a new flootty")

    options, args = parser.parse_args()

    out('\nThe dream has begun.\n')
    f = Flooty(options)
    atexit.register(f.cleanup)
    f.connect()
    f.select()
    out('\nThe dream is (probably) over.\n')


class FD(object):
    def __init__(self, fileno, reader=None, writer=None, errer=None):
        self.fileno = fileno
        self.reader = reader
        self.writer = writer
        self.errer = errer

    def __getitem__(self, key):
        return getattr(self, key, None)


class Flooty(object):
    '''
    This class does the actual work of the pseudo terminal. The spawn() function is the main entrypoint.
    '''

    def __init__(self, options):
        self.master_fd = None
        self.old_handler = None
        self.mode = None
        self.host = 'localhost'
        self.port = 5678
        self.fds = {}
        self.readers = set()
        self.writers = set()
        self.errers = set()
        self.empty_selects = 0
        self.buf_out = Queue.Queue()
        self.options = options
        self.finished_startup = False

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

    def transport(self, name, data=""):
        self.buf_out.put({"name": name, "data": data}, True)

    def select(self):
        '''
        Main select loop. Passes all data to self.master_read() or self.stdin_read().
        '''
        attrs = ('errer', 'reader', 'writer')
        while True:
            try:
                _in, _out, _except = select.select(self.readers, self.writers, self.errers)
            except (IOError, OSError) as e:
                return
            except (select.error, socket.error, Exception) as e:
                # Interrupted system call.
                if e[0] == 4:
                    continue
                err('Error in select(): %s' % str(e))
                return self.reconnect()

            for position, fds in enumerate([_except, _in, _out]):
                attr = attrs[position]
                for fd in fds:
                    handler = self.fds[fd][attr]
                    if handler:
                        handler(fd)

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
            out(buf)
        else:
            self.empty_selects += 1
            if self.empty_selects > 10:
                err('No data from sock.recv() {0} times.'.format(self.empty_selects))
                return self.reconnect()

    def cloud_write(self, fd):
        while True:
            try:
                item = self.buf_out.get_nowait()
            except Queue.Empty:
                break
            else:
                self.sock.sendall(json.dumps(item) + '\n')

    def cloud_err(self, err):
        self.reconnect()

    def reconnect(self):
        out('not reconnecting\n')
        sys.exit()

    def connect(self):
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
        self.add_fd(self.sock, reader=self.cloud_read, writer=self.cloud_write, errer=self.cloud_err)
        out(str(self.readers), str(self.writers))
        self.reconnect_delay = INITIAL_RECONNECT_DELAY
        if not self.finished_startup:
            self.startup()
            self.finished_startup = True

    def get_list(self):
        self.transport("list")

    def startup(self):
        if self.options.list:
            return self.get_list()
        elif self.options.join:
            self.action = self.join
            self.value = self.options.create
        elif self.options.create:
            self.action = 'create'
            self.value = self.options.create

    def spawn(self, argv=None):
        '''
        Create a spawned process.
        Based on the code for pty.spawn().
        '''
        assert self.master_fd is None
        if not argv:
            argv = [os.environ['SHELL']]

        pid, master_fd = pty.fork()
        self.master_fd = master_fd
        if pid == pty.CHILD:
            os.execlp(argv[0], *argv)

        self.old_handler = signal.signal(signal.SIGWINCH, self._signal_winch)
        try:
            self.mode = tty.tcgetattr(pty.STDIN_FILENO)
            tty.setraw(pty.STDIN_FILENO)
        except tty.error:    # This is the same as termios.error
            pass

        self._set_pty_size()
        self.add_fd(master_fd, reader=self.master_read)
        self.add_fd(pty.STDIN_FILENO, reader=self.stdin_read)

    def cleanup(self):
        mode = getattr(self, 'mode')
        if mode:
            tty.tcsetattr(pty.STDIN_FILENO, tty.TCSAFLUSH, mode)
        if self.master_fd:
            os.close(self.master_fd)
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

    def write_master(self, data):
        '''
        Writes to the child process from its controlling terminal.
        '''
        master_fd = self.master_fd
        assert master_fd is not None
        while data != '':
            n = os.write(master_fd, data)
            data = data[n:]

    def master_read(self, fd):
        '''
        Called when there is data to be sent from the child process back to the user.
        '''
        data = os.read(fd, 1024)
        flag = findlast(data, ALTERNATE_MODE_FLAGS)
        if flag is not None:
            if flag in START_ALTERNATE_MODE:
                # This code is executed when the child process switches the terminal into alternate mode. The line below assumes that the user has opened vim, and writes a message.
                # self.write_master('IEntering special mode.\x1b')
                pass
            elif flag in END_ALTERNATE_MODE:
                # This code is executed when the child process switches the terminal back out of alternate mode. The line below assumes that the user has returned to the command prompt.
                # self.write_master('echo "Leaving special mode."\r')
                pass
        if data:
            self.transport("stdout", data)
            out(data)

    def stdin_read(self, fd):
        '''
        Called when there is data to be sent from the user/controlling terminal down to the child process.
        '''
        data = os.read(fd, 1024)
        self.write_master(data)
        if data:
            self.transport("stdin", data)

if __name__ == '__main__':
    main()
