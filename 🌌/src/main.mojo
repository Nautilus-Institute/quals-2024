from sys import argv
from util import input, fatal
from benchmark.compiler import keep

from app import App
from server import Server, Request, Response
from async_runtime import CoroutineRuntime, async_sleep

# =============================================================

async fn super[f: Server.route_fn_type](
    inout serv: Server,
    owned req: Request,
    owned res: Response
) -> Int:
    if not serv.app.session:
        fatal("SECURITY BREACH")
        return 0

    var ident = serv.app.get_session_ident()
    if ident != "super":
        fatal("SECURITY BREACH")
        return 0

    print("Entering Super route")
    return await f(serv, req, res)

async fn index(
    inout serv: Server,
    owned req: Request,
    owned res: Response
) -> Int:
    _= await async_sleep(1000)

    res.send_body("You are wired into the system")
    return 0

async fn auth(
    inout serv: Server,
    owned req: Request,
    owned res: Response
) -> Int:
    var token = req.next_param_str()
    var is_valid = await serv.app.validate_token(token^)
    if not is_valid:
        fatal("SECURITY BREACH")
        return 0
    res.send_body("authenticated")
    return 0

async fn register(
    inout serv: Server,
    owned req: Request,
    owned res: Response
) -> Int:
    var ident = req.next_param_str()
    _= await serv.app.generate_session(ident^)
    res.send_body("[Register][Token]" + serv.app.session_token + "[$Token][$Register]")
    return 0

async fn entry_flag(
    inout serv: Server,
    owned req: Request,
    owned res: Response
) -> Int:
    var flag_1 = String(argv()[1])
    res.send_body("[Flag1]" + flag_1 + "[$Flag1]")
    return 0

# =============================================================

async fn database_info(
    inout serv: Server,
    owned req: Request,
    owned res: Response
) -> Int:
    print('[Signal][Inspect]')
    serv.inspect_info()
    serv.app.inspect_info()
    print('[$Inspect][Signal]')
    return 0

async fn name_route(
    inout serv: Server,
    owned req: Request,
    owned res: Response
) -> Int:
    print("Entering Name route")
    _ = await serv.app.set_database_name(req^, res^)
    return 0

async fn clear_route(
    inout serv: Server,
    owned req: Request,
    owned res: Response
) -> Int:
    print("Entering Clear route")
    _= await serv.app.clear_database(req^, res^)
    return 0

async fn scour_route(
    inout serv: Server,
    owned req: Request,
    owned res: Response
) -> Int:
    print("Entering Scour route")
    _= await serv.app.scour_fragments(req^, res^)
    return 0

async fn deflect_route(
    inout serv: Server,
    owned req: Request,
    owned res: Response
) -> Int:
    print("Entering Processing route")
    _ = await serv.app.deflect_fragments(req^, res^)
    return 0

async fn create_collections_route(
    inout serv: Server,
    owned req: Request,
    owned res: Response
) -> Int:
    print("Entering Create Collections route")
    _ = await serv.app.create_collections(req^, res^)
    return 0

async fn ingest_fragment_route(
    inout serv: Server,
    owned req: Request,
    owned res: Response
) -> Int:
    print("Entering Insert Doc route")
    _ = await serv.app.ingest_fragment(req, res)
    return 0

# =================================================================

fn init_routes(inout server: Server):
    server.route('index',   index)
    server.route('auth',    auth)
    server.route('reg',     register)
    server.route('flag1',   super[entry_flag])
    # ===========================================
    server.route('scour',   scour_route)
    server.route('col',     create_collections_route)
    server.route('ingest',  ingest_fragment_route)
    server.route('clear',   super[clear_route])
    server.route('name',    super[name_route])
    server.route('deflect', super[deflect_route])
    server.route('inspect', super[database_info])

from python import Python

fn main() raises:
    print("[Wired]Reaching out; Contact system***[$Wired]")

    var name = "jocol"
    var app = App(name)
    app.init()

    var server = Server(app^)
    init_routes(server)

    CoroutineRuntime.spawn_task(server.run_server_loop())

    CoroutineRuntime.async_run_tasks()()

    keep(server)