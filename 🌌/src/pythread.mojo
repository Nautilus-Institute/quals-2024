from python import Python
from collections import Optional
from benchmark.compiler import keep

from util import PyList, fatal
from async_runtime import (
    READY_TYPE_PY_THREAD, READY_TYPE_PY_THREAD_DEADLINE,
    CoroutineRuntime, async_sleep
)

var pythread: Optional[PythonObject] = None
fn get_pythread() -> PythonObject:
    if pythread:
        return pythread.value()
    try:
        Python.add_to_path('./src/')
        pythread = Python.import_module('pythread').ServerThread
    except e:
        print("Error importing pythread.py module: ", e)
    if not pythread:
        fatal("Failed to import pythread.py module")
    return pythread.value()

fn get_thread_result(id: String) -> PythonObject:
    var thread = get_pythread()
    try:
        return thread.get_thread_result(id)
    except e:
        print("Error getting thread result: ", e)
    fatal("Failed to get thread result")
    return None


fn is_thread_complete(owned id: String) -> Bool:
    var thread = get_pythread()
    try:
        if thread.is_thread_complete(id):
            return True
        return False
    except e:
        print("Error checking if thread is complete: ", e)
    fatal("Failed to check if thread is complete")
    return False

fn run_py_func_in_thread(owned func: String, owned args: List[PythonObject], is_background: Bool=False) -> String:
    var thread = get_pythread()
    var pyargs = PyList.from_list(args)
    try:
        var id = thread.run_in_thread(func, pyargs.list, is_background)
        return id
    except e:
        print("Error running python function in thread: ", e)
    fatal("Failed to start python thread")
    return ""

from util import now_ms

@value
struct PyFunc:
    "Allows mojo to call a python function in a thread, and async await until it completes. Python functions must be registered with `ServerThread.register(name,fn)`."
    var func: String
    var id: String
    # Background threads run in separate python procs
    var background: Bool
    # MS to wait for thread before aborting (if >0)
    var deadline: Int
    var start_time: Int

    fn __init__(inout self, owned func: String):
        self.id = ""
        self.func = func^
        self.background = False
        self.deadline = 0
        self.start_time = 0

    async fn async_run_py_func(inout self, owned args: List[PythonObject]) -> Int:
        self.start_time = now_ms()

        var id: String = run_py_func_in_thread(self.func, args^, self.background)
        self.id = id

        if is_thread_complete(id):
            # Thread is already complete, no reason to await
            return 0

        if self.deadline > 0:
            # Causes the await to resume after deadline
            _= await async_sleep(self.deadline, READY_TYPE_PY_THREAD_DEADLINE, id)

            # If we didn't complete, then we failed the deadline
            if not is_thread_complete(id):
                fatal("Thread did not complete before deadline")
                
        else:
            _= await async_sleep(100, READY_TYPE_PY_THREAD, id)

        keep(id)
        return 0

    fn get_result(inout self) -> PythonObject:
        return get_thread_result(self.id)
