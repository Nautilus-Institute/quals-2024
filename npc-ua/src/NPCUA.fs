// For more information see https://aka.ms/fsharp-console-apps
open MBrace.FsPickler
open MBrace.FsPickler.Json
open System
open System.IO
open System.Net
open System.Reflection
open crypto.nautilus

open FSharp.Json

let _JsonConfig = JsonConfig.create(allowUntyped = true, unformatted = true)
let _JsonSerializer = FsPickler.CreateJsonSerializer(indent = false, omitHeader = true)

let mutable log_level = 0

let writeToStderr (s: string) = Console.Error.WriteLine (s)
let dontWrite(s: string) = ()
//let debug_printfn format = eprintf
  //Printf.ksprintf writeToStderr format
let debug_printfn (format)=
  fun ([<ParamArray>] arr) -> ()
  //Printf.ksprintf dontWrite format


// TODO input sanitizer that limits what is passed to the router
// has some kind of bug that lets you request an arbitrary remote resoruce but not arbitrary system resource
// 

// https://reference.opcfoundation.org/Core/Part3/v105/docs/4

type AttributeId =
  | NodeId = 1
  | NodeClass = 2
  | DisplayName = 4
  | Description = 5
  | Value = 13

type Node() =
  // Static method to check if a node is known
  static member Known(target: Uri) =
    false

  abstract Serialize: unit -> string
  default this.Serialize() =
      _JsonSerializer.PickleToString(this :> System.Object)

  abstract Allowed_attributes: AttributeId list 
  default this.Allowed_attributes = []

  abstract Read_attribute: AttributeId -> obj option
  default this.Read_attribute(aid: AttributeId) =
    None
  abstract Write_attribute: AttributeId * obj -> bool
  default this.Write_attribute(aid: AttributeId, v: obj) =
    false

type VariableNode(name: string, init_val: obj) as this =
  inherit Node()

  static let mutable Variables = Map.empty<string, VariableNode>
  let mutable variable: obj = init_val 

  do
    this.Install()

  member this.name = name

  member this.Install() =
    Variables <- Variables.Add(name, this)

  override this.Serialize() =
    let _name = this.name
    let _variable = variable
    let importVariableNode() =
      VariableNode(_name, _variable)

    _JsonSerializer.PickleToString(importVariableNode :> System.Object)

  static member Find(target: Uri) =
    let p = target.AbsolutePath
    let n = Variables.TryFind(p)
    if n.IsSome then
      Some(n.Value :> Node)
    else
      None
      //Some(VariableNode(p))

  override this.Allowed_attributes = [
    AttributeId.NodeId; 
    AttributeId.NodeClass;
    AttributeId.DisplayName;
    AttributeId.Description;
    AttributeId.Value
  ]
  override this.Read_attribute(aid: AttributeId) =
    if aid = AttributeId.NodeId then
      Some(("npc://Variable"+this.name) :> obj)
    else if aid = AttributeId.DisplayName then
      Some(this.name)
    else if aid = AttributeId.Value then
      Some(variable)
    else
      None

  override this.Write_attribute(aid: AttributeId, v: obj) =
      variable <- v 
      true

VariableNode("/version","npc://System/Environment/Version") |> ignore
VariableNode("/environment","production") |> ignore

type SystemNode(path: string) =
  inherit Node()
  let path = path

  static member GetSystemProperty(path: string) =
    debug_printfn "Getting system property %s" path 
    let parts = path.Split("/")
    let asm_name = parts[0];
    let type_name = parts[1];
    let prop_name = parts[2];
    let asm = Assembly.Load(asm_name);
    let ty = asm.GetType(type_name, false, false);
    let prop = ty.GetProperty(prop_name);
    let v = prop.GetValue(null, null);
    v.ToString()

  static member Find(target: Uri) =
    let p = target.AbsolutePath
    let n: Node = SystemNode(p)
    Some(n)

  override this.Allowed_attributes = [
    AttributeId.NodeId; 
    AttributeId.NodeClass;
    AttributeId.DisplayName;
    AttributeId.Description;
    AttributeId.Value
  ]
  override this.Read_attribute(aid: AttributeId) =
    let p = path.TrimStart('/')
    let sys_name = "System.Private.CoreLib/System."+p
    if aid = AttributeId.NodeId then
      Some(("npc://System/" + p) :> obj)
    else if aid = AttributeId.DisplayName then
      Some(sys_name)
    else if aid = AttributeId.Value then
      Some(SystemNode.GetSystemProperty(sys_name))
    else
      None

  override this.Write_attribute(aid: AttributeId, v: obj) =
    false

type NodeManager() =
  static member Find(target: string) =
    let target = Uri(target)
    let host = target.Host.ToLower()
    debug_printfn "Finding node %O" target
    debug_printfn "Finding host %s" target.Host
    if target.Scheme <> "npc" then
      Option<Node>.None
    elif host = "system" then
      SystemNode.Find(target)
    elif host = "variable" then
      VariableNode.Find(target)
    else
      None


// A function to read a csv file and create a map from SymbolName to (StatusCode and Description)
let loadStatusCodes (fileName: string) =
  // Open the file for reading
  use reader = new System.IO.StreamReader(fileName)
  // Create an empty map
  let mutable map = Map.empty
  // Loop through the lines of the file
  while not reader.EndOfStream do
    // Read a line and split it by comma
    let line = reader.ReadLine()
    let fields = line.Split(',')
    // Extract the SymbolName, StatusCode and Description fields
    let symbolName = fields.[0]
    let statusCode = int fields.[1]
    let description = fields.[2]
    // Remove quotes from description
    let description = description.Substring(1, description.Length - 2)
    // Add the entry to the map
    //debug_printfn "Adding `%s`" symbolName
    map <- map.Add(symbolName, (statusCode, description))
  // Return the map
  map

  

// TODO query function
    

// Server can send unsigned "references"
// Malicious server sends reference to local server `System.Private.CoreLib/System.Environment/Version`
// This leaks the hashcode seed to the user
// User uses "echo" node to find generate colliding signatures
// Solves for private key
// Uses that to sign objects coming from the malicious server

type BitWriter(data: byte array)=
  let mutable pre_data = data
  let mutable post_data: byte array = Array.empty

  member this.data() =
    Array.concat [ pre_data; post_data ]

  member this.length() =
    this.data().Length

  member this.append(bw: BitWriter)=
    this.bytes(bw.data())
  member this.append(data: byte array)=
    pre_data <- Array.concat [ pre_data; data ]

  member this._set_post_data(data: byte array) =
    post_data <- data

  member this.prepender() =
    let bw = BitWriter(Array.empty)
    bw._set_post_data(this.data())
    bw
  
  member this.postpender() =
    let bw = BitWriter(this.data())
    bw

  member this.write(s: Stream) =
    s.Write(this.data(), 0, this.length())

  member this.bytes(data: byte array) =
    this.append(data)

  member this.u8(i: byte) =
    let bytes = [| i |]
    this.bytes(bytes)

  member this.u32(i: int32) =
    let bytes = BitConverter.GetBytes(i);
    this.bytes(bytes)

  member this.u64(i: int64) =
    let bytes = BitConverter.GetBytes(i);
    this.bytes(bytes)

  member this.str(s: string) =
    let bytes = System.Text.Encoding.UTF8.GetBytes(s);
    this.u32(bytes.Length)
    this.bytes(bytes)
  
  member this.byte_array(b: byte array) =
    this.u32(b.Length)
    this.bytes(b)

type BitReader(data: byte array) =
  let data = data
  let offset: int ref = ref 0

  member this.bytes(length: int) =
    // if length is 0 or -1 then return empty array
    if length <= 0 then
      [||]
    else
      let b = data.[!offset..(!offset+length-1)]
      offset := !offset + length
      b

  member this.u32() =
    let b = this.bytes(4)
    BitConverter.ToUInt32(b, 0)
  
  member this.u64()=
    let b = this.bytes(8)
    BitConverter.ToUInt64(b, 0)

  member this.u16()=
    let b = this.bytes(2)
    BitConverter.ToUInt16(b, 0)
  
  member this.byte_str() =
    let length = this.u32()
    this.bytes(int length)
  
  member this.str() =
    let b = this.byte_str()
    System.Text.Encoding.UTF8.GetString(b)
  
  member this.qualified_name() =
    let ns = this.u16()
    let name = this.str()
    name
  
  member this.rest() =
    this.bytes(data.Length - !offset)

  member this.node_id()=
    let id_type = this.u32()
    if id_type = 0u then
      // Numeric
      let id = this.u32()
      id.ToString()
    elif id_type = 1u then
      // String
      this.str()
    elif id_type = 2u then
      // Guid
      let b = this.bytes(16)
      System.Guid(b).ToString()
    elif id_type = 3u then
      null
      // Opaque
      //let b = this.bytes(16)
      //System.Guid(b).ToString()
    else
      // Unknown
      null

// TODO handle invalid type
let tryFindMapValueAsType<'T> (map: Map<string, obj>) (key: string) =
  match map.TryFind(key) with
  | Some v -> Some (v :?> 'T)
  | None -> None

let int32Option (d: decimal option) =
  match d with
  | Some(d) -> Some (int32 d)
  | None -> None
let int64Option (d: decimal option) =
  match d with
  | Some(d) -> Some (int64 d)
  | None -> None

let tryFindMapValueAsTypeDefault<'T> (map: Map<string, obj>) (key: string) (def: 'T) =
  match map.TryFind(key) with
  | Some v -> v :?> 'T
  | None -> def
  

// https://reference.opcfoundation.org/Core/Part4/v104/docs/7.28#_Ref129000063
type RequestHeader = {
  authToken: string option
  timestamp: int64
  requestHandle: int32
  returnDiagnostics: int32 option
  auditEntryId: string option
  timeoutHint: int32 option
}

// https://reference.opcfoundation.org/Core/Part4/v104/docs/7.29#_Ref115239340
type ResponseHeader = {
  timestamp: int64
  requestHandle: int32
  serviceResult: uint32
  serviceDiagnostics: obj option
  stringTable: string array
}

type NodeId = {
  IdType: int
  Id: string
}

type ReadValue = {
  nodeId: NodeId 
  attributeId: int32
  indexRange: string
  dataEncoding: string
}

type ReadService = {
  requestHeader: RequestHeader
  maxAge: int32
  timestampsToReturn: int32
  nodesToRead: ReadValue array
}

type SignedData = {
  data: string
  signature: string
}

type ListResultsResponse = {
  responseHeader: ResponseHeader
  results: obj list
  diagnosticInfos: obj list
}


type DataValue = {
  value: obj option
  statusCode: uint32
  sourceTimestamp: int64
  sourcePicoseconds: int32
  serverTimestamp: int64
  serverPicoseconds: int32
  error: string option
}

type StatusCode = {
  statusCode: uint32
  error: string option
}


type ErrorResponse = {
  responseHeader: ResponseHeader
  error: string
  diagnosticInfos: obj array
}

let mutable application_pubkey = null;

let pubkey_path = "public.ec.pem"

type CryptoSystem(loadPublicKey: unit -> unit, loadPrivateKey: unit -> Crypto) =
  let privateKey = loadPrivateKey()

  do loadPublicKey()

  member this.VerifyString(data: string, signature: string) =
    privateKey.VerifyString(data, signature)
  member this.SignString(data: string) =
    privateKey.SignString(data)

let GetCryptoSystem(key_path) =
  let pub_key_path = key_path + "/" + "public.ec.pem"
  let priv_key_path = key_path + "/" + "private.ec.pem"
  let loadPublicKey () =
    application_pubkey <- File.ReadAllBytes(pub_key_path)
  let loadPrivateKey () =
    Crypto(priv_key_path)
  //let tmp = _JsonSerializer.PickleToString(loadPublicKey :> obj)
  //printfn "EXP: %s" tmp
  CryptoSystem(loadPublicKey, loadPrivateKey)

// Create a static map of error codes to error messages and initialize it
let mutable error_map = Map.empty<int, string>
error_map <- error_map.Add(0x80010000, "Unknown error")

type NPCUA(inputIn: Stream, outputIn: Stream) =
  let input = inputIn 
  let output = outputIn

  let status_codes = loadStatusCodes "StatusCode.csv"
  //let crypto = Crypto("private.ec.pem")
  let crypto = GetCryptoSystem(".")

  let mutable foo = ""

  let send_sec = false
  
  member this.start_connection() =
    while true do
      this.read_msg()
  
    //https://reference.opcfoundation.org/Core/Part4/v104/docs/#5.6.2
  
  // https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.2
  member this.send_msg(name: string, bw: BitWriter) =
    let hw = bw.prepender()
    hw.bytes(System.Text.Encoding.ASCII.GetBytes(name))
    hw.u8(byte 0)
    hw.u32(bw.length() + 8)
    hw.write(output)

  member this.send_sec_msg(name: string, bw: BitWriter) =
    let mutable sec_id = 0
    let mutable sec_policy = "http://nautilus.npc/UA/SecurityPolicy#None"
    if send_sec then
      sec_id <- 1
      sec_policy <- "http://nautilus.npc/UA/SecurityPolicy#Basic256Sha256"
    
    let hw = bw.prepender()
    hw.u32(sec_id)

    // Security Header
    hw.str(sec_policy)
    hw.byte_array(application_pubkey)
    hw.u32(0)

    // Sequence Header
    hw.u32(0)
    hw.u32(0)

    // TODO sign sec_data and append signature

    this.send_msg(name, hw)

  member this.read_sec_msg_header(br: BitReader) = 
    let sec_id = br.u32()
    let sec_policy = br.str()
    let sec_pubkey = br.byte_str()
    let sec_token = br.u32()
    // TODO make sure sec_token is 0
    let seq_num = br.u32()
    let req_id = br.u32()
    (sec_id, sec_policy, sec_pubkey, sec_token, seq_num, req_id)

  // https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.4
  member this.send_ack() =
    let b = BitWriter(Array.empty)
    b.u32(1337)
    b.u32(0x1000)
    b.u32(0x1000)
    b.u32(0x1000)
    b.u32(0x1)
    this.send_msg("ACK", b)
  
  member this.get_status_code(name:string) =
    let status = status_codes |> Map.find name
    status |> fst 

  member this.get_status_message(name:string) =
    let status = status_codes |> Map.find name
    status |> snd

  // https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.5
  // https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.5#_Ref164020643
  member this.send_err(name: string) =
    let status = status_codes |> Map.find name
    let code = status |> fst
    let msg = status |> snd
    let b = BitWriter(Array.empty)
    b.u32(code)
    b.str(msg)
    this.send_msg("ERR", b)

  
  // https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
  member this.handle_hello(br: BitReader) =
    let version = br.u32()
    let recv_buf = br.u32()
    let send_buf = br.u32()
    let max_msg = br.u32()
    let max_chunk = br.u32()
    let endpoint = br.str()
    this.send_ack()

  member this.send_service_response(res: obj) =
    let res_str: string = Json.serializeEx _JsonConfig  res
    let bw = BitWriter(Array.empty)
    // Convert res to utf-8 bytes
    let bytes = System.Text.Encoding.UTF8.GetBytes(res_str)
    bw.bytes(bytes)
    this.send_sec_msg("MSG", bw)

  member this.send_service_err(name: string, req: RequestHeader option) =
    let status = status_codes |> Map.find name
    let code = status |> fst
    let msg = status |> snd
    this.send_service_response({
      responseHeader = this.make_response_header(name, req);
      error = msg
      diagnosticInfos = Array.empty;
    })

  // https://reference.opcfoundation.org/Core/Part4/v104/docs/6.3.2
  member this.handle_msg(br: BitReader) =
    this.read_sec_msg_header(br) |> ignore

    let versionTime = br.u32()
    let num_namespaces = br.u32()
    num_namespaces |> ignore
    //if num_namespaces > 0u then
    //  for i in 0..int num_namespaces-1 do
    //    let ns = br.str()
    //    ns |> ignore
    let num_server_uris = br.u32()
    num_server_uris |> ignore
    //if num_server_uris > 0u then
    //  for i in 0..int num_server_uris-1 do
    //    let uri = br.str()
    //    uri |> ignore
    let num_locales = br.u32()
    num_locales |> ignore
    //if num_locales > 0u then
    //  for i in 0..int num_locales-1 do
    //    let locale = br.str()
    //    locale |> ignore
    let service_id = br.u32()
    // Print service id
    debug_printfn "Service ID: %d" service_id

    this.handle_service_request(br, service_id)

  member this.handle_service_request(br: BitReader, service_id: uint32) =
    let json_data_opt: Map<string, obj> option = this.get_json_request(br)
    if json_data_opt.IsNone then
      this.send_service_err("BadDecodingError", None)
    else
    let json_data: Map<string, obj> = json_data_opt.Value

    let reqh_opt: RequestHeader option = this.get_service_request_header(json_data)
    if reqh_opt.IsNone then
      this.send_service_err("BadInvalidArgument", None)
    else
    let reqh = reqh_opt.Value

    // https://python-opcua.readthedocs.io/en/latest/opcua.ua.html
    // XXXRequest =
    match service_id with
    | 629u -> this.handle_read_service(json_data, reqh)
    | 630u -> this.handle_write_service(json_data, reqh)
    | 631u -> this.handle_export_service(json_data, reqh)
    | 632u -> this.handle_import_service(json_data, reqh)
    | _ -> this.send_err("BadServiceUnsupported")

  member this.make_response_header(status: string, reqh: RequestHeader option) =
    { 
      timestamp = DateTime.Now.ToFileTimeUtc();
      requestHandle = if reqh.IsSome then reqh.Value.requestHandle else 0;
      serviceResult = uint32 (this.get_status_code(status));
      serviceDiagnostics = None;
      stringTable = Array.empty;
    }

  member this.get_service_request_header(json: Map<string, obj>) =
    let reqh = tryFindMapValueAsType<Map<string, obj>> json "requestHeader"
    if reqh = None then
      None
    else
      let reqh_map = reqh.Value
      Some({
        authToken = tryFindMapValueAsType<string> reqh_map "authToken";
        timestamp = int64 (tryFindMapValueAsTypeDefault<decimal> reqh_map "timestamp" (decimal 0)); 
        requestHandle = int32 (tryFindMapValueAsTypeDefault<decimal> reqh_map "requestHandle" (decimal 0));
        returnDiagnostics = int32Option (tryFindMapValueAsType<decimal> reqh_map "returnDiagnostics");
        auditEntryId = tryFindMapValueAsType<string> reqh_map "auditEntryId";
        timeoutHint =  int32Option (tryFindMapValueAsType<decimal> reqh_map "timeoutHint");
      })


  member this.get_json_request(br: BitReader)=
    let json_str =
      try
        let rest: byte array = br.rest()
        let utf_str = System.Text.Encoding.UTF8.GetString(rest)
        // Print byte array rest
        //debug_printfn "rest: %s" utf_str
        Some(utf_str)
      with
        | _  -> None

    if json_str.IsSome then
      try
        Option<Map<string, obj>>.Some(
          Json.deserializeEx<Map<string, obj>> _JsonConfig json_str.Value)
      with
        | _  -> None
    else
      None

  member this.handle_import_service(json: Map<string, obj>, reqh: RequestHeader) =
    let nodes = tryFindMapValueAsType<obj list> json "nodesToImport"
    if nodes.IsNone then
      this.send_service_err("BadInvalidArgument", Some(reqh))
    else
    let nodes = nodes.Value

    let res: obj list = nodes |> List.map (fun json ->
      let make_res(n) = 
        {
          statusCode = uint (this.get_status_code(n));
          error = if n = "Good" then None else Some(this.get_status_message(n));
        }

      if not (json :? Map<string, obj>) then
        make_res("BadInvalidArgument")
      else
      let json = json :?> Map<string, obj>

      let signed_data = tryFindMapValueAsType<string> json "data"
      let sig_data = tryFindMapValueAsType<string> json "signature"
      if signed_data.IsNone || sig_data.IsNone then
        make_res("BadInvalidArgument")
      else
      let signed_data = signed_data.Value
      let sig_data = sig_data.Value
      let is_valid = crypto.VerifyString(signed_data, sig_data)
      debug_printfn "==== is_valid: %O" is_valid

      if not is_valid then
        make_res("BadUserSignatureInvalid")
      else

      let out = _JsonSerializer.UnPickleOfString<System.Object> signed_data
      debug_printfn "@@@@@@@ %O" out

      if (out :? FSharpFunc<Unit, unit>) then
        let f = out :?> FSharpFunc<Unit, unit>
        f()
        make_res("Good")
        //BadInvalidArgument
      else if (out :? VariableNode) then
        let n = out :?> VariableNode
        n.Install()
        make_res("Good")
      else
      make_res("BadNotExecutable")
    )

    this.send_service_err("Good", Some(reqh))

  member this.handle_export_service(json: Map<string, obj>, reqh: RequestHeader) =
    let nodes = tryFindMapValueAsType<obj list> json "nodesToExport"
    if nodes.IsNone then
      this.send_service_err("BadInvalidArgument", Some(reqh))
    else
    let nodes = nodes.Value

    let res: obj list = nodes |> List.map (fun json ->
      let make_res(n, v) = 
        {
          value = v;
          statusCode = uint (this.get_status_code(n));
          sourceTimestamp = 0;
          sourcePicoseconds = 0;
          serverTimestamp = 0;
          serverPicoseconds = 0;
          error = if n = "Good" then None else Some(this.get_status_message(n));
        }

      if not (json :? Map<string, obj>) then
        make_res("BadInvalidArgument", None)
      else
      let json = json :?> Map<string, obj>

      let node_id = tryFindMapValueAsType<string> json "nodeId"
      if node_id.IsNone then
        make_res("BadNodeIdInvalid", None)
      else
      let node_id = node_id.Value
      
      let node = NodeManager.Find(node_id)
      if node.IsNone then
        make_res("BadNodeIdUnknown", None)
      else
      let node = node.Value

      //let json_out = _JsonSerializer.PickleToString(node :> System.Object)
      let json_out = node.Serialize()

      let sig_data = crypto.SignString(json_out)
      debug_printfn "==== value sig: %s" sig_data
      let is_valid = crypto.VerifyString(json_out, sig_data)
      debug_printfn "==== is_valid: %O" is_valid

      let value = {
        data = json_out;
        signature = sig_data;
      }
      make_res("Good", Some(value))
    )

    //let seed = this.get_system_property("System.Private.CoreLib/System.Marvin/DefaultSeed");
    //let res = [| seed |]
    this.send_service_response({
      responseHeader = this.make_response_header("Good", Some(reqh));
      results = res;
      diagnosticInfos = List.empty;
    })

    //this.send_service_err("Good", Some(reqh))


  // https://reference.opcfoundation.org/Core/Part4/v104/docs/5.10.4
  member this.handle_write_service(json: Map<string, obj>, reqh: RequestHeader)=
    let nodes = tryFindMapValueAsType<obj list> json "nodesToWrite"
    if nodes.IsNone then
      this.send_service_err("BadInvalidArgument", Some(reqh))
    else
    let nodes = nodes.Value

    if nodes.Length = 0 then
      this.send_service_err("BadNothingToDo", Some(reqh))
    else

    let res: obj list = nodes |> List.map (fun json ->
      let make_res(n, v) = 
        {
          statusCode = uint (this.get_status_code(n));
          error = if n = "Good" then None else Some(this.get_status_message(n));
        }

      if not (json :? Map<string, obj>) then
        make_res("BadInvalidArgument", None)
      else
      let json = json :?> Map<string, obj>

      let node_id = tryFindMapValueAsType<string> json "nodeId"
      if node_id.IsNone then
        make_res("BadNodeIdInvalid", None)
      else
      let node_id = node_id.Value

      let node = NodeManager.Find(node_id)
      if node.IsNone then
        make_res("BadNodeIdUnknown", None)
      else
      let node = node.Value

      let attr = (tryFindMapValueAsType<decimal> json "attributeId")
      if attr.IsNone then
        make_res("BadAttributeIdInvalid", None)
      else
      let attr = enum<AttributeId>(int attr.Value)

      let value = json.TryFind "value"
      if value.IsNone then
        make_res("BadInvalidArgument", None)
      else
      let value = value.Value
      
      if node.Allowed_attributes |> List.contains attr then
        if node.Write_attribute(attr, value) then
          make_res("Good", value)
        else
          make_res("BadAttributeIdInvalid", value)
      else
        make_res("BadNodeAttributesInvalid", None)
    )
    this.send_service_response({
      responseHeader = this.make_response_header("Good", Some(reqh));
      results = res;
      diagnosticInfos = List.empty;
    })

//  member this.get_node_and_attr_from_req

  // https://reference.opcfoundation.org/Core/Part4/v104/docs/5.10.2
  member this.handle_read_service(json: Map<string, obj>, reqh: RequestHeader)=
    let nodes = tryFindMapValueAsType<obj list> json "nodesToRead"
    if nodes.IsNone then
      this.send_service_err("BadInvalidArgument", Some(reqh))
    else
    let nodes = nodes.Value

    (*
    let x = tryFindMapValueAsType<string> json "data"
    debug_printfn "----- data: %s" x.Value

    foo <- x.Value
    *)

    if nodes.Length = 0 then
      //let seed = this.get_system_property("System.Private.CoreLib/System.Marvin/DefaultSeed");
      //let res = [| seed |]
      this.send_service_response({
        responseHeader = this.make_response_header("Good", Some(reqh));
        results = List.empty;
        //results = res;
        diagnosticInfos = List.empty;
      })
    else
    // Map nodes
    let res: obj list = nodes |> List.map (fun json ->
      let make_res(n, v) = 
        {
          value = v;
          statusCode = uint (this.get_status_code(n));
          sourceTimestamp = 0;
          sourcePicoseconds = 0;
          serverTimestamp = 0;
          serverPicoseconds = 0;
          error = if n = "Good" then None else Some(this.get_status_message(n));
        }

      if not (json :? Map<string, obj>) then
        make_res("BadInvalidArgument", None)
      else
      let json = json :?> Map<string, obj>

      let node_id = tryFindMapValueAsType<string> json "nodeId"
      if node_id.IsNone then
        make_res("BadNodeIdInvalid", None)
      else
      let node_id = node_id.Value
      
      let node = NodeManager.Find(node_id)
      if node.IsNone then
        make_res("BadNodeIdUnknown", None)
      else
      let node = node.Value

      let attr = (tryFindMapValueAsType<decimal> json "attributeId")
      if attr.IsNone then
        make_res("BadAttributeIdInvalid", None)
      else
      let attr = enum<AttributeId>(int attr.Value)

      if not (node.Allowed_attributes |> List.contains attr) then
        make_res("BadNodeAttributesInvalid", None)
      else

      let value = node.Read_attribute(attr)
      if value.IsNone then
        make_res("BadAttributeIdInvalid", value)
      else
      let value = value.Value

      if not (value :? string) then
        make_res("Good", Some(value))
      else
      let str_value = value :?> string

      let str_value = "\"" + str_value + "\""

      let sig_data = crypto.SignString(str_value)
      debug_printfn "==== value sig: %s" sig_data
      let is_valid = crypto.VerifyString(str_value, sig_data)
      debug_printfn "==== is_valid: %O" is_valid

      let value = {
        data = str_value;
        signature = sig_data;
      }
      make_res("Good", Some(value))
    )
    this.send_service_response({
      responseHeader = this.make_response_header("Good", Some(reqh));
      results = res;
      diagnosticInfos = List.empty;
    })

  member this.read_u32() =
    let b = Array.zeroCreate<byte> 4
    input.Read(b, 0, 4) |> ignore
    BitConverter.ToInt32(b, 0)
  
  member this.read_bytes(length: int) =
    let b = Array.zeroCreate<byte> length
    input.Read(b, 0, length) |> ignore
    b

  member this.read_msg() =
    let header = this.read_bytes(4) // Read in the header
    let length = BitConverter.ToUInt32(this.read_bytes(4), 0) // Read in the length
    let data = this.read_bytes(int length - 8) // Read in the data
    let br = BitReader(data)

    let name = System.Text.Encoding.ASCII.GetString(header, 0, 3);
    match name with
    | "HEL" -> this.handle_hello(br)
    | "MSG" -> this.handle_msg(br)
    //| "MSG" -> this.handle_msg(data)
    //| "CLO" -> this.handle_(data)
    | _ -> this.send_err("BadServiceUnsupported")


    // Read in a uint32 from `input`


//  member this.test() =
//
//    let seed = this.get_system_property("System.Private.CoreLib/System.Marvin/DefaultSeed");
//    //let seed = this.get_system_property("System.Private.CoreLib/System.Environment/Version");
//    debug_printfn "seed: %O" seed
//
//    let s: string = "Hello world"
//    let hc = s.GetHashCode()
//    debug_printfn "hash %x" hc

  member this.get_system_property(path: string) =
    let parts = path.Split("/")
    let asm_name = parts[0];
    let type_name = parts[1];
    let prop_name = parts[2];
    let asm = Assembly.Load(asm_name);
    let ty = asm.GetType(type_name, false, false);
    let prop = ty.GetProperty(prop_name);
    let v = prop.GetValue(null, null);
    v

  










  //member this.hello() =

let start_app() =



  let input = Console.OpenStandardInput()
  let output = Console.OpenStandardOutput()
  let ua = NPCUA(input, output)
  ua.start_connection() |> ignore
  //ua.test() |> ignore
  1

start_app() |> ignore
