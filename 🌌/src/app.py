import json
import time
import sys
import re
import os
from hashlib import sha1

from util import printex, limit_ascii

try:
    from pythread import ServerThread

    class App(object):
        SECRET_KEY: bytes = open('/secret.key', 'rb').read()

        EXISTING_USERS: set = set(['super'])

        @staticmethod
        @ServerThread.register('App.generate_session')
        @printex
        def generate_session(ident):
            #print("[PY] Generating session.....")
            ident = limit_ascii(ident)

            collide = False
            if ident in App.EXISTING_USERS:
                collide = True

            for u in App.EXISTING_USERS:
                for c in u:
                    if c in ident:
                        collide = True
                        break

            if collide:
                ident += os.urandom(8).hex()
            
            App.EXISTING_USERS.add(ident)
            return {'ident': ident}

        @staticmethod
        @ServerThread.register('App.generate_session_token')
        @printex
        def generate_session_token(session: dict):
            j = json.dumps(session)
            h = sha1(j.encode() + App.SECRET_KEY).hexdigest()
            return f'{h}|{j}|'

        @staticmethod
        @ServerThread.register('App.load_token')
        @printex
        def load_token(token: str):
            if not App.validate_token(token):
                raise Exception("Invalid token")

            token_body = token.split('{',1)[1].split('|',1)[0]

            return json.loads('{'+token_body)

        @staticmethod
        def validate_token(token: str):
            token = token.encode()
            sig, data = token.split(b'|',2)[:2]
            calc = sha1(data + App.SECRET_KEY).hexdigest()

            if sig == calc.encode():
                return True

            return False

        # ===================================================

        @staticmethod
        @ServerThread.register('App.matches_filter')
        @printex
        def matches_filter(filter, value):
            invert = False

            if filter.startswith('!'):
                filter = filter[1:]
                invert = True

            if len(filter) == 0:
                return not invert

            res = bool(re.match(filter, value))
            return bool(res ^ invert)

except Exception as e:
    print("[PY] Error While Loading `app.py`:", e)
    import traceback
    traceback_str = traceback.format_exc()
    print("[PY] Traceback", traceback_str)
    sys.stdout.flush()
    raise e