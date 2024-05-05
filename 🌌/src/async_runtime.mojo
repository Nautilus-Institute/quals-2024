"""
Mojo's open source stdlib includes coroutines, but no actual runtime to run them...
So here is a simple coroutine runtime which supports async_sleep
How it works:
- When a coroutine calls async_sleep:
    - It is suspended
    - It is added to a waiting list
- Then the runtime iterates over all waiting coroutines:
    - If a coroutine is ready to wake up, it is resumed
- If no coroutines are ready, the runtime sleeps the thread for a bit
"""
from collections import Optional
from builtin.coroutine import _CoroutineContext, _coro_resume_noop_callback

from pythread import is_thread_complete
from util import fatal, get_uuid4, now_ms, sleep_ms

struct CoroutineWrapper[type: AnyRegType]:
    """This wrapper makes the Coroutine implement CollectionElement trait so we can move it into the list."""

    var _handle: Coroutine[type]

    fn __init__(inout self, owned handle: Coroutine[type]):
        self._handle = handle^
    
    fn __moveinit__(inout self, owned other: CoroutineWrapper[type]):
        self._handle = other._handle^
    
    fn __copyinit__(inout self, other: CoroutineWrapper[type]):
        fatal("Not allowed to copy Coroutine")
        self._handle = Coroutine[type](other._handle._handle)


var READY_TYPE_SLEEP = 0
var READY_TYPE_PY_THREAD = 1
var READY_TYPE_PY_THREAD_DEADLINE = 2

@value
struct CoroutineWaiter:
    """This struct is used to keep track of coroutines that are waiting to be resumed."""

    var handle: Coroutine[Int]._handle_type
    var wakeup_time: Int # ms
    var finished: Bool
    var uuid: String
    var ready_type: Int

    fn __init__(
        inout self,
        handle: Coroutine[Int]._handle_type,
        wakeup_time: Int = 0
    ):
        self.handle = handle
        self.finished = False
        self.wakeup_time = wakeup_time
        self.uuid = get_uuid4()
        self.ready_type = READY_TYPE_SLEEP

    fn is_ready_sleep(self: CoroutineWaiter) -> Bool:
        "Simply check if the current time is greater than the wakeup time."
        return now_ms() >= self.wakeup_time

    fn is_ready_py_thread(self: CoroutineWaiter) -> Bool:
        "Check if the python thread has completed or the deadline has passed."

        # If we have a deadline, check if that wakes us up
        if self.ready_type == READY_TYPE_PY_THREAD_DEADLINE:
            if self.is_ready_sleep():
                return True

        return is_thread_complete(self.uuid)

    fn is_ready(inout self) -> Bool:
        "Check if the coroutine is ready to be resumed, based on the ready type."
        if self.ready_type == READY_TYPE_SLEEP:
            return self.is_ready_sleep()
        elif (
            self.ready_type == READY_TYPE_PY_THREAD
            or self.ready_type == READY_TYPE_PY_THREAD_DEADLINE
        ):
            return self.is_ready_py_thread()
        else:
            return False

# Lists of sleeping coroutines
var coroutines: List[CoroutineWrapper[Int]] = List[CoroutineWrapper[Int]]()
var coroutine_waiters: List[CoroutineWaiter] = List[CoroutineWaiter]()

var num_waiting_coroutines: Int = 0

@value
struct CoroutineRuntime:
    @staticmethod
    fn add_waiting_coroutine(
        owned co: Coroutine[Int],
        sleep_dur_ms: Int,
        ready_type: Int = 0,
        owned id: String = ""
    ):
        """
        Add a coroutine to the runtime which will resume after sleep_dur_ms milliseconds.
        """

        var now = now_ms()
        var wakeup_time = now + sleep_dur_ms

        var h = CoroutineWaiter(co._handle, wakeup_time)

        h.ready_type = ready_type
        if len(id) > 0:
            h.uuid = id

        coroutine_waiters.append(h^)

        # To prevent the coroutine from __del__ing and cancling the coroutine when we leave scope
        # we will move it into a global list so the lifetime does not expire
        var w = CoroutineWrapper(co^)
        coroutines.append(w^)

        num_waiting_coroutines += 1

    @staticmethod
    fn spawn_task(
        owned co: Coroutine[Int],
        ready_type: Int = 0
    ):
        """
        Prepare a top-level coroutine to be run alongside other coroutines.
        """
        # Mark the coroutine as a top-level coroutine that does not return to any parent (similar to stdlib/src/builtin/coroutine.mojo __call__)
        co._get_ctx[_CoroutineContext]().store(
            # Task has no parent coroutine
            _CoroutineContext {
                _resume_fn: _coro_resume_noop_callback,
                _parent_hdl: _CoroutineContext._opaque_handle.get_null(),
            }
        )

        # Start as soon as possible
        CoroutineRuntime.add_waiting_coroutine(co^, 0)

    @staticmethod
    async fn async_run_tasks():
        CoroutineRuntime.resume_waiting_coroutines()


    @staticmethod
    fn resume_waiting_coroutines():
        """
        Keep running coroutines until there are no more waiting.
        This must be called from inside a coroutine.
        Please use `CoroutineRuntime.async_run_tasks()()` to run this function from outside a coroutine.
        """
        while True:
            if num_waiting_coroutines == 0:
                print("[Warn] CoroutineRuntime: No waiting coroutines, exiting loop")
                return
            
            CoroutineRuntime.resume_next_waiting_coroutine()

    @staticmethod
    fn resume_next_waiting_coroutine():
        """
        Find the next coroutine which is ready to wake up and resume it.
        """
        var length = len(coroutine_waiters)

        if num_waiting_coroutines == 0:
            print("[Warn] CoroutineRuntime: No waiting coroutines, exiting loop")
            return

        var target_index = -1

        # Find the next coroutine which is ready to wake up
        for i in range(length):
            var w = coroutine_waiters[i]
            if w.finished:
                continue

            if not w.is_ready():
                continue

            target_index = i
            break

        if target_index < 0 or target_index >= length:
            sleep_ms(100)
            return

        # Prepare to resume the coroutine
        var w = coroutine_waiters[target_index]

        num_waiting_coroutines -= 1

        w.finished = True
        coroutine_waiters[target_index] = w

        # Actually resume the coroutine via mlir
        __mlir_op.`pop.coroutine.resume`(w.handle)

        return


async fn async_thunk() -> Int:
    return 0

from benchmark.compiler import keep

async fn async_sleep(
    n_sec: Int,
    ready_type: Int = 0,
    owned id: String= ""
) -> Int:
    # Create a target coroutine, but we won't await it yet
    # Instead we will add it in a suspended state
    # And allow the runtime to resume it after n seconds
    var co = async_thunk()

    # To re-enter the runtime loop, we await the following code block
    __mlir_region await_body():
        # Tell the runtime to resume this coroutine after n seconds
        CoroutineRuntime.add_waiting_coroutine(co^, n_sec, ready_type, id)

        # In the meantime, we will yield to the runtime
        # We will then ask the runtime to find the next coroutine to resume
        #print("async_sleep()[await]: Yielding to runtime...")
        CoroutineRuntime.resume_waiting_coroutines()

        #print("async_sleep()[await]: Resumed from runtime")
        __mlir_op.`pop.coroutine.await.end`()


    # Actually suspend the coroutine via mlir
    __mlir_op.`pop.coroutine.await`[_region = "await_body".value]()

    # Keep locals alive until the coroutine is resumed
    keep(id)
    keep(n_sec)
    keep(ready_type)

    # Pass along the return value of the coroutine
    return co.get()