from python import Python
from collections import Optional

from app import App
from pythread import PyFunc
from util import fatal, unwrap
from async_runtime import CoroutineRuntime, async_sleep

var py_server: Optional[PythonObject] = None
fn get_py_server() -> PythonObject:
    if py_server:
        return py_server.value()
    try:
        Python.add_to_path('./src/')
        py_server = Python.import_module('server').Server.create_stdio()
    except e:
        print("Failed to import server.py module: ", e)
    if not py_server:
        fatal("Failed to import server.py module")
    return py_server.value()

@value
struct RouteFunction:
    alias fn_type = async fn(
        inout serv: Server,
        owned req: Request,
        owned res: Response
    ) -> Int
    var func: Self.fn_type

    fn __str__(self) -> String:
        return (
            Reference(self.func)
            .get_unsafe_pointer()
            .bitcast[Pointer[Int64]]()
            .load()
        )

# == Compiler Fix ==
# Due to a Mojo compiler limitation, async function pointers don't correctly infer that they return a Coroutine when called
# To correct this, we cast the function pointer to one that explicitly returns a Coroutine. This is not a type confusion.
@register_passable
struct RouteFunctionCo:
    alias route_fn_co = async fn(
        inout serv: Server,
        owned req: Request,
        owned res: Response
    ) -> Coroutine[Int]
    var func: Self.route_fn_co

    @staticmethod
    fn fix_async_fn_ptr(
        func: RouteFunction
    ) -> RouteFunctionCo:
        var p = Reference(func)
            .get_unsafe_pointer()
            .bitcast[RouteFunctionCo]()
        return p.load()

# == End Compiler Fix ==

# Allow calling a python function and async sleeping until it completes

from util import PyList, string_from_py_bytes

@value
struct Request:
    var target: String
    var pyreq: PythonObject

    fn __init__(inout self):
        self.target = ""
        self.pyreq = None

    fn from_py(inout self, owned pyreq: PythonObject) raises:
        self.target = string_from_py_bytes(pyreq.target)
        self.pyreq = pyreq^

    fn assert_has_param(self):
        if not self.has_next_param():
            fatal("Request has no more params")

    fn has_next_param(self) -> Bool:
        try:
            if self.pyreq.has_next_param():
                return True
            return False
        except e:
            print("Failed to check next param: ", e)
        return False
    
    fn next_param_str(inout self) -> String:
        self.assert_has_param()
        try:
            var s: String = string_from_py_bytes(self.pyreq.next_param())
            return s
        except e:
            print("Failed to get next param: ", e)
        return ""

    fn next_param_int(inout self) -> Int:
        try:
            return int(self.next_param_str())
        except e:
            print("Failed to convert param to int: ", e)
        return 0


@value
struct Response:
    var body: String

    fn send_body(inout self, owned body: String):
        self.body = body^
        print("[Signal]" + self.body + "[$Signal]")

async fn null_route(
    inout serv: Server,
    owned req: Request,
    owned res: Response
) -> Int:
    return 0

@value
struct Route:
    var func: RouteFunction
    var name: String

    @staticmethod
    fn null() -> Route:
        return Route(RouteFunction(null_route), "null")

    fn __str__(self) -> String:
        return "<route " + self.name + " at " + str(self.func) + ">"
    


var g_routes: List[Route] = List[Route]()

@value
struct Server:
    var app: App
    var running: Bool

    alias route_fn_type = RouteFunction.fn_type

    def __init__(inout self, owned app: App):
        self.app = app^
        self.running = True

    fn route(inout self, owned name: String, owned func: RouteFunction.fn_type):
        var route = Route(RouteFunction(func), name)
        g_routes.append(route)

    async fn run_server_loop(inout self) -> Int:
        "Continuously read requests and handle them."
        while self.running:
            var req = Request()
            _= await self.read_request(req)

            var res = Response('')
            _= await self.handle_route(req^, res^)

            _= await async_sleep(500)

        return 0

    fn inspect_info(inout self):
        print("Registered Routes:")
        for r in g_routes:
            print(r[])


    # ====== Implementation ======

    fn find_route_for_request(inout self, inout req: Request) -> Optional[Route]:
        "Look through all the registered routes and find the one that matches the request target."
        var target: String = req.target

        for r in g_routes:
            if r[].name == target:
                return r[]
        
        return None

    async fn handle_route(inout self, owned req: Request, owned res: Response) -> Int:
        "Create a coroutine for the route (if exists) and run it."

        var route = self.find_route_for_request(req)
        if not route:
            res.send_body('[Deadend$]')
            return -1
        var route_ = List[Route](route.value())

        var f = route.value().func

        # Cast the type of the callback function to the correct type
        # See `fix_callback_type` for more details
        var f_async = RouteFunctionCo.fix_async_fn_ptr(f)

        # Get the suspended coroutine for the task
        var co = f_async.func(self, req, res)

        CoroutineRuntime.spawn_task(co^)

        return 0


    async fn read_request(self, inout req: Request) -> Int:
        var server = get_py_server()

        var pf = PyFunc('Server.read_request')
        pf.deadline = 30000
        _= await pf.async_run_py_func(List[PythonObject]())

        var res = pf.get_result()
        if not res:
            fatal("Result is null")

        try:
            req.from_py(res)
        except e:
            print("Error reading request: ", e)
            fatal("Failed to read request")

        return 0
