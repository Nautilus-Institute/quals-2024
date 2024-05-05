from python import Python
from time import sleep, now
from testing import assert_true
from collections import Optional
from python.python import _get_global_python_itf
from python._cpython import CPython, PyObjectPtr
from collections.vector import InlinedFixedVector

var util_py_mod: Optional[PythonObject] = None
fn get_util_py() -> PythonObject:
    if util_py_mod:
        return util_py_mod.value()
    try:
        Python.add_to_path('./src')
        util_py_mod = Python.import_module('util')
    except e:
        print("Error importing util.py module", e)
    if not util_py_mod:
        fatal("Failed to import util.py module")
    return util_py_mod.value()

fn input(s: String):
    try:
        Python.import_module("builtins").input(s)
    except:
        pass
    print("Continuing...")

fn unwrap[T: CollectionElement](value: Optional[T]) -> T:
    if not value:
        fatal("Attempted to unwrap empty Optional value")
    return value.value()

fn abort():
    print("Program aborted....")
    var p = Pointer[Int](1869246317)
    p.store(500136108641)

fn fatal(error: String):
    print("[FATAL ERROR]: " + error)
    abort()

fn flush_stdout():
    try:
        Python.import_module("sys").stdout.flush()
    except:
        pass

fn get_uuid4() -> String:
    try:
        return Python.import_module("uuid").uuid4().hex
    except:
        fatal("Failed to generate UUID4")
    return ""

fn now_sec() -> Int:
    return now() // 1000000000

fn now_ms() -> Int:
    return now() // 1000000

fn sleep_ms(ms: Int):
    var start = now_ms()
    var delta = ms / 1000
    sleep(delta)
    var end = now_ms()
    if end - start < ms:
        fatal("Sleep Interrupted")

fn py_get_builtin_type(borrowed expr: String) -> PythonObject:
    var util_py = get_util_py()
    try:
        return util_py.get_builtin_type(expr)
    except e:
        print("Error evaluating expression", e)
    fatal("Failed to evaluate expression")
    return None

@register_passable
struct PyList(CollectionElement, Sized):
    var list: PythonObject

    fn __init__(inout self):
        var util_py = get_util_py()
        self.list = py_get_builtin_type("list")

    fn __init__(inout self, list: PythonObject):
        self.list = list

    fn __copyinit__(inout self, other: PyList):
        self.list = other.list

    fn __getitem__(self, index: Int) -> Optional[PythonObject]:
        try:
            return self.list[index]
        except e:
            print("Error getting item from PyList", e)
        return None

    fn __len__(self) -> Int:
        try:
            return len(self.list)
        except e:
            print("Error getting length of PyList", e)
        fatal("Failed to get length of PyList")
        return 0

    fn to_list_string(self) -> List[String]:
        var result = List[String]()

        var l = len(self)
        result.reserve(l)

        for i in range(l):
            var item = self[i]
            if not item:
                continue
            var value = item.value()
            var s: String = value
            result.append(s^)

        return result^

    @staticmethod
    fn from_list(borrowed list: List[PythonObject]) -> PyList:
        var py_list = PyList()
        try:
            for item in list:
                py_list.list.append(item[])
            return py_list^
        except e:
            print("Error creating PyList from List", e)
            fatal("Failed to create PyList from List")
        return PyList()

    @staticmethod
    fn from_list(borrowed list: List[String]) -> PyList:
        var py_list = PyList()
        try:
            for item in list:
                py_list.list.append(item[])
            return py_list^
        except e:
            print("Error creating PyList from List", e)
            fatal("Failed to create PyList from List")
        return PyList()


fn PyBytes_AsString(borrowed cpython: CPython, py_bytes: PyObjectPtr) -> StringRef:
    "Calls the cpython function PyBytes_AsStringAndSize to get the bytes object as a string."
    var data: DTypePointer[DType.int8] = DTypePointer[DType.int8](0)
    var length: Int = 0

    cpython.lib.get_function[
        fn (PyObjectPtr, Pointer[DTypePointer[DType.int8]], Pointer[Int])
        -> None
    ]("PyBytes_AsStringAndSize")(
        py_bytes,
        Reference(data).get_unsafe_pointer(),
        Reference(length).get_unsafe_pointer()
    )

    return StringRef(
        data,
        length
    )

fn string_from_py_bytes(py_bytes: PythonObject) -> String:
    "Helper method to construct a byte String from a python bytes object."
    var cpython = _get_global_python_itf().cpython()
    var mojo_str = String(
        PyBytes_AsString(cpython, py_bytes.py_object)
    )
    #print("@@@@@@@@@@@@@@@@ After converting to string: ", mojo_str)
    return mojo_str
    