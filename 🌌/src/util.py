import sys
import json

list = list
dict = dict
json = json

def get_builtin_type(name):
    flush_stdout()
    return eval(f'{name}()')

from functools import wraps

def limit_ascii(val):
    if isinstance(val, str):
        val = val.encode('ascii')
    if isinstance(val, bytes):
        val = val.decode('ascii')
    if not isinstance(val, str):
        val = str(val)
    
    return ''.join(
        c for c in val
        if c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_ !@#$%^&*()-_=+[]{}|;:,.<>?/\\\'"'
    )

def printex(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print("[PY] Exception in", func, e)
            import traceback
            stack = traceback.format_exc()
            print("[PY] Stack\n", stack)
            sys.stdout.flush()
            raise e
    return wrapper

def flush_stdout():
    sys.stdout.flush()
