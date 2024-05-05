import sys
import threading
from uuid import uuid4

from util import printex
try:
    from pythread import ServerThread

    class Request(object):
        def __init__(self, **kwargs):
            self.target = kwargs.get('target', None)
            self.params = kwargs.get('params', [])
            self.param_index = 0
        
        def __str__(self):
            return f"Request(target={self.target}, params={self.params})"
        
        def __repr__(self):
            return str(self)

        @printex
        def has_next_param(self):
            sys.stdout.flush()
            return len(self.params) > self.param_index
        
        @printex
        def next_param(self):
            if not self.has_next_param():
                return None
            res = self.params[self.param_index]
            self.param_index += 1
            sys.stdout.flush()
            return res


    class Server(object):
        INST = None

        def __init__(self):
            Server.INST = self
            ServerThread.register('Server.read_request', self.read_request)

        def parse_req(self, line: bytes):
            line = line.strip()
            req = Request()

            target, res = line.split(b'|',1)

            req.target = target
            req.params = res.split(b',')

            return req

        @printex
        def read_request(self):
            print('[Enquiry]')
            sys.stdout.flush()

            line = sys.stdin.buffer.readline().strip()
            return self.parse_req(line)

        @classmethod
        def create_stdio(cls):
            return cls()

except Exception as e:
    print("[PY] Error loading module server.py:", e)
    import traceback
    traceback_str = traceback.format_exc()
    print("[PY] Traceback", traceback_str)
    sys.stdout.flush()
    raise e