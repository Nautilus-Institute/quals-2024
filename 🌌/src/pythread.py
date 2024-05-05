import time
import sys
import threading
import multiprocessing as mp
from uuid import uuid4
from typing import Dict
from multiprocessing import Pool

from util import printex

try:
    MAX_THREADS = 4

    class ServerThread(object):
        STATUS_RUNNING = uuid4()
        STATUS_COMPLETE = uuid4()

        ALL_THREADS: Dict[str,"ServerThread"] = dict()
        NUM_THREADS = 0

        ALL_FUNCS: Dict[str, "function"] = dict()

        @classmethod
        def get_func_by_name(cls, name):
            if name in cls.ALL_FUNCS:
                return cls.ALL_FUNCS[name]
            return None

        @classmethod
        def register(cls, name, func=None):
            def decorator(func):
                cls.ALL_FUNCS[name] = func
                return func
            if not func:
                return decorator
            return decorator(func)

        @classmethod
        @printex
        def is_thread_complete(cls, thread_id) -> bool:
            thread = ServerThread.get_thread(thread_id)
            return thread.status != ServerThread.STATUS_RUNNING

        @classmethod
        @printex
        def get_thread_result(cls, thread_id):
            thread = ServerThread.get_thread(thread_id)
            return thread.result

        @classmethod
        @printex
        def get_thread(cls, thread_id) -> "ServerThread":
            return ServerThread.ALL_THREADS.get(thread_id, None)

        @classmethod
        @printex
        def run_in_thread(cls, target_name, args, is_background) -> str:
            target = cls.get_func_by_name(target_name)
            t = ServerThread(target, *args)
            t.background = is_background
            t.start()

            # Give the thread a chance to finish sync before awaiting it
            t.wait(.1)

            return t.id

        def __init__(self, target, *args):
            self.id = str(uuid4())
            self.target = target
            self.args = list(args)
            self.status = ServerThread.STATUS_RUNNING
            self.thread = None
            self.result = None
            self.background = False

        @staticmethod
        def entrypoint(self_id):
            self = ServerThread.ALL_THREADS[self_id]

            self.status = ServerThread.STATUS_RUNNING
            self.result = None

            try:
                if self.background:
                    # Some actions can block the global interpreter lock
                    # This breaks the await mechanism, so we run those in a separate process via a pool
                    try:
                        mp.set_start_method('spawn')
                    except:
                        pass
                    with Pool(processes=1) as pool:
                        self.result = pool.apply(self.target, self.args)
                else:
                    self.result = self.target(*self.args)

            except Exception as e:
                print("[PY] Thread error", e)
                import traceback
                stack = traceback.format_exc()
                print("[PY] Stack\n", stack)
                self.result = None

            self.status = ServerThread.STATUS_COMPLETE
            self.NUM_THREADS -= 1

        def wait(self, timeout=None):
            # Do a sync wait until the thread finishes or the timeout is reached
            start = time.time()
            while self.status == ServerThread.STATUS_RUNNING:
                time.sleep(0.01)
                if timeout and time.time() - start > timeout:
                    return False
            return True

        def start(self):
            if self.NUM_THREADS >= MAX_THREADS:
                raise Exception("Too many threads")

            ServerThread.ALL_THREADS[self.id] = self
            self.NUM_THREADS += 1

            self.thread = threading.Thread(
                target=ServerThread.entrypoint,
                args=(self.id,)
            )
            self.thread.daemon = True
            self.thread.start()

except Exception as e:
    print("[PY] Error while loading module pythread.py", e)
    import traceback
    traceback_str = traceback.format_exc()
    print("[PY] Traceback", traceback_str)
    sys.stdout.flush()
    raise e