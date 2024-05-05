from python import Python
from benchmark.compiler import keep
from server import Request, Response
from collections import Optional, List

from pythread import PyFunc
from util import fatal, flush_stdout

var py_app: Optional[PythonObject] = None
fn get_py_server() -> PythonObject:
    if py_app:
        return py_app.value()
    try:
        Python.add_to_path('./src/')
        py_app = Python.import_module('app').App
    except e:
        print("Failed to import server.py module: ", e)
    if not py_app:
        fatal("Failed to import server.py module")
    return py_app.value()

@value
struct Fragment:
    var id: Int
    var history: List[String]

    fn __init__(inout self, owned data: String):
        self.id = 0
        self.history = List[String](data^)

    fn get(inout self) -> String:
        var current_data = String()
        if len(self.history) > 0:
            current_data = self.history.__get_ref(-1)[]
        return current_data^

@value
struct Collection:
    var name: String
    var fragments: List[Fragment]
    fn __init__(inout self):
        self.fragments = List[Fragment]()
        self.fragments.reserve(1)
        self.name = "foo"

    fn __len__(self) -> Int:
        return len(self.fragments)

    fn add_fragment(inout self, owned doc: Fragment):
        self.fragments.append(doc^)

    fn inspect_print(borrowed self):
        print("| |--- Collection", self.name)
        print("| |-", len(self.fragments), "fragments")

@value
struct Database:
    var collections: List[Collection]
    fn __init__(inout self):
        self.collections = List[Collection]()

    fn __len__(self) -> Int:
        return len(self.collections)

    fn add_collection(inout self, owned col: Collection):
        self.collections.append(col^)

    fn inspect_print(borrowed self):
        print("|--- Database")
        print("| |-", len(self.collections), "collections")
        for col in self.collections:
            col[].inspect_print()

@value
struct App:
    var name: String
    var database: Database
    var session: PythonObject
    var session_token: String

    fn __copyinit__(inout self, other: Self):
        fatal("Copy init not supported")
        self = App("")

    fn __init__(inout self, owned name: String):
        self.database = Database()
        self.name = name^
        self.session = None
        self.session_token = String("")

    fn inspect_print(borrowed self):
        self.database.inspect_print()


    fn init(inout self) raises:
        var pyapp = get_py_server()

        var d = Fragment("~~~")

        var c = Collection()
        c.add_fragment(d^)

        self.database.add_collection(c^)

    fn inspect_info(inout self):
        self.inspect_print()

    async fn get_session_token(
        inout self
    ) -> Int:
        var pf = PyFunc('App.generate_session_token')
        pf.deadline = 1000
        pf.background = True

        var args = List[PythonObject](self.session)
        _= await pf.async_run_py_func(args^)

        self.session_token = pf.get_result()
        return 0

    async fn generate_session(
        inout self,
        owned token: String
    ) -> Int:
        var pf = PyFunc('App.generate_session')
        pf.deadline = 1000
        pf.background = True

        var args = List[PythonObject](token^)
        _= await pf.async_run_py_func(args^)

        self.session = pf.get_result()

        _= await self.get_session_token()
        return 0

    fn get_session_ident(
        inout self
    ) -> String:
        if not self.session:
            return String("")
        try:
            var get_username = self.session.get('ident')
            return get_username
        except e:
            print("Error:", e)
            fatal("Failed to get ident from session")
        return ""

    async fn validate_token(
        inout self,
        owned token: String
    ) -> Int:
        var pf = PyFunc('App.load_token')
        pf.deadline = 1000

        var args = List[PythonObject](token^)

        _= await pf.async_run_py_func(args^)

        var session = pf.get_result()
        self.session = session^

        if self.session:
            return 1
        return 0

    # ===========================================

    async fn clear_database(
        inout self,
        owned req: Request,
        owned res: Response,
    ) -> Int:
        "Clear all collections and fragments."
        self.database.collections.clear()

        res.send_body("All Fragments Purged")

        return 0

    async fn set_database_name(
        inout self,
        owned req: Request,
        owned res: Response,
    ) -> Int:
        "Set the name of the database entity."
        var name = req.next_param_str()
        self.name = name^

        return 0

    async fn ingest_fragment(
        inout self,
        owned req: Request,
        owned res: Response,
    ) -> Int:
        "Ingest a fragment into a specified collection index."
        var col_ind = req.next_param_int()
        if col_ind < 0 or col_ind >= len(self.database):
            var err = (
                "Could not find collection #"
                + str(col_ind)
                +", you only have "
                + str(len(self.database))
                +" collections"
            )
            res.send_body(err)
            return 0
        
        var frag = Fragment(req.next_param_str())
        var col_ref = self.database.collections.__get_ref(col_ind)
        col_ref[].add_fragment(frag^)

        var frag_ind = len(col_ref[])-1

        res.send_body('Fragment Ingested #'+str(col_ind)+','+str(frag_ind))
        return 0


    async fn create_collections(
        inout self,
        owned req: Request,
        owned res: Response,
    ) -> Int:
        "Create 1 or more collections with given names."
        var n = req.next_param_int()

        self.database.collections.reserve(len(self.database) + n)
        for i in range(n):
            if not req.has_next_param():
                fatal("Missing collection name")

            var c = Collection()
            c.name = req.next_param_str()
            self.database.add_collection(c^)

        res.send_body("Collections Created")

        return 0

    async fn does_fragment_match(
        inout self: Self,
        inout doc: Fragment,
        borrowed filter: String,
    ) -> Int:
        "Check if a fragment matches a regex filter."

        # Mojo does not support regex matching in its stdlib yet
        var pf = PyFunc('App.matches_filter')
        pf.background = True
        pf.deadline = 5000

        var current_data = doc.get()
        var args = List[PythonObject](filter, current_data^)

        _= await pf.async_run_py_func(args^)

        var filter_matches = pf.get_result()

        if not filter_matches:
            return 0
        return 1


    alias match_action_fn = async fn(
        inout self: Self,
        inout res: Response,
        inout frag: Fragment,
        borrowed value: String,
    ) -> Int

    @staticmethod
    async fn scour_fragment(
        inout self: Self,
        inout res: Response,
        inout frag: Fragment,
        borrowed value: String,
    ) -> Int:
        "Respond with the fragment data."
        var response = '[Fragment]' + frag.get() + '[$Fragment]'
        res.send_body(response)
        return 0

    @staticmethod
    async fn deface_fragment(
        inout self: Self,
        inout res: Response,
        inout frag: Fragment,
        borrowed value: String,
    ) -> Int:
        "Change the fragment data."
        var new_value = value

        keep(frag.history) # XXX is this needed
        frag.history.append(new_value)

        keep(frag)
        return 0

    async fn matching_fragments[match_f: Self.match_action_fn](
        inout self,
        owned req: Request,
        owned res: Response,
        owned database: Database,
        owned filter: String,
        owned value: String,
    ) -> Int:
        "Given a database, filter, value, and a list of fragments (via req), find all of the set that match and apply a function to them."
        var num_found = 0

        while req.has_next_param():
            var col_ind = req.next_param_int()
            var frag_ind = req.next_param_int()

            # Check if the collection exists
            var num_cols = len(self.database)
            if col_ind < 0 or col_ind >= num_cols:
                var err = (
                    "Could not find collection #"
                    + str(col_ind)
                    +", you only have "
                    + str(num_cols)
                    +" collections"
                )
                res.send_body(err)
                continue

            # Check if the fragment exists
            var num_docs = len(database.collections.__get_ref(col_ind)[])
            if frag_ind < 0 or frag_ind >= num_docs:
                var err = (
                    "Could not find fragment #"
                    + str(frag_ind)
                    +", you only have "
                    + str(num_docs)
                    +" fragments in the collection"
                )
                res.send_body(err)
                continue
            
            var frag_ref = (
                self.database.collections.__get_ref(col_ind)[]
                .fragments.__get_ref(frag_ind)
            )

            # Check if the fragment matches the filter
            var does_match = 1
            if len(filter) > 0:
                does_match = await self.does_fragment_match(
                    frag_ref[],
                    filter,
                )
            
            if does_match:
                # If so, await the provided async function
                num_found += 1
                if does_match:
                    _= await match_f(
                        self,
                        res,
                        frag_ref[],
                        value,
                    )

            keep(frag_ref)

        return num_found

    async fn deflect_fragments(
        inout self,
        owned req: Request,
        owned res: Response,
    ) -> Int:
        "Deflect matching fragments."
        var filter = req.next_param_str()
        var update_value = req.next_param_str()

        var num_found = await self.matching_fragments[
            Self.deface_fragment
        ](
            req, res,
            self.database,
            filter,
            update_value,
        )

        res.send_body("Fragments Deflected *" + str(num_found))
        return 0

    async fn scour_fragments(
        inout self,
        owned req: Request,
        owned res: Response,
    ) -> Int:
        "Scour matching fragments."
        var filter = req.next_param_str()

        var num_found = await self.matching_fragments[
            Self.scour_fragment
        ](
            req, res,
            self.database,
            filter,
            "",
        )
        res.send_body("Fragments Scoured *" + str(num_found))
        return 0
