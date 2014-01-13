import subprocess
import re
import fcntl
import os.path

try:
    from .. import event_emitter, msg, shared as G
    assert event_emitter and G and msg
except (ImportError, ValueError):
    from floo.common import event_emitter, msg, shared as G


class ProxyProtocol(event_emitter.EventEmitter):
    ''' Base Proxy Interface'''

    def __init__(self):
        super(ProxyProtocol, self).__init__()
        try:
            from .. import reactor
        except (ImportError, ValueError):
            from floo.common import reactor
        self.reactor = reactor.reactor
        self.cleanup()

    def __len__(self):
        return 0

    def fileno(self):
        return self.fd

    def fd_set(self, readable, writeable, errorable):
        if self.fd:
            readable.append(self.fd)
            errorable.append(self.fd)

    def cleanup(self):
        try:
            self._proc.kill()
        except Exception:
            pass
        self.fd = None
        self._proc = None
        self.buf = [b'']
        try:
            self.reactor._protos.remove(self)
        except Exception:
            pass

    def read(self):
        data = b''
        while True:
            try:
                d = os.read(self.fd, 65535)
                if not d:
                    break
                data += d
            except IOError:
                break
        self.buf[0] += data
        if not data:
            return
        lines = self.buf[0].decode('utf-8').split('\n')
        self.buf[0] = lines[-1].encode('utf-8')
        msg.debug("Floobits SSL proxy output: %s" % '\n'.join(lines[:-1]))

    def error(self):
        self.cleanup()

    def reconnect(self):
        self.cleanup()

    def stop(self):
        self.cleanup()

    def connect(self, args):
        self._proc = proc = subprocess.Popen(args, cwd=G.PLUGIN_PATH, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        line = proc.stdout.readline().decode('utf-8')
        self.fd = proc.stdout.fileno()
        fl = fcntl.fcntl(self.fd, fcntl.F_GETFL)
        fcntl.fcntl(self.fd, fcntl.F_SETFL, fl | os.O_NONBLOCK | os.O_ASYNC)

        msg.log("Read line from Floobits SSL proxy: %s" % line)
        match = re.search('Now listening on <(\d+)>', line)
        if not match:
            raise Exception("Couldn't find port in line from proxy: %s" % line)
        self._port = int(match.group(1))
        self.reactor._protos.append(self)
        return self._port
