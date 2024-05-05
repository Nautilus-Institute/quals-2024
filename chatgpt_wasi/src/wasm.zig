const std = @import("std");

// Define WebAssembly section IDs
const Section = enum(u8) {
    Custom = 0,
    Type = 1,
    Import = 2,
    Function = 3,
    Table = 4,
    Memory = 5,
    Global = 6,
    Export = 7,
    Start = 8,
    Element = 9,
    Code = 10,
    Data = 11,
    DataCount = 12,
};

// Define WebAssembly value types
pub const ValType = enum(u8) {
    I32 = 0x7F,
    I64 = 0x7E,
    F32 = 0x7D,
    F64 = 0x7C,
    V128 = 0x7B,
    funcref = 0x70,
    externref = 0x6F,
    functype = 0x60,
    _,
};

pub const Value = struct {
    t: ValType,
    mutable: bool,
    v: u64,

    pub fn format(self: Value, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        _ = try writer.print("Value({any} = {} (0x{x}))", .{ self.t, self.v, self.v });
    }
};

fn dump_hex(bytes: []const u8) void {
    //std.debug.dump_hex(bytes);
    _ = bytes;
}

fn debugprint(comptime fmt: []const u8, args: anytype) void {
    //std.debug.print(fmt, args);
    _ = fmt;
    _ = args;
}

// Define the structure of a WebAssembly module
pub const Module = struct {
    types: std.ArrayList(FunctionSignature),
    globals: std.ArrayList(Global),
    definitions: std.ArrayList(FunctionDefinition),
    functions: std.ArrayList(Function),
    exports: std.ArrayList(Export),
    dataSegments: std.ArrayList(DataSegment),
    customSections: std.ArrayList(CustomSection),
    elements: std.ArrayList(Element),
    imports: std.ArrayList(Import),
    tables: std.ArrayList(Table),
    memory: std.ArrayList(Memory),
    startFunc: ?u32,

    pageAlloc: std.mem.Allocator,
    alloc: std.mem.Allocator,

    const Self = @This();

    pub fn init(alloc: std.mem.Allocator) !Self {
        var r = Self{
            .globals = std.ArrayList(Global).init(alloc),
            .functions = std.ArrayList(Function).init(alloc),
            .definitions = std.ArrayList(FunctionDefinition).init(alloc),
            .types = std.ArrayList(FunctionSignature).init(alloc),
            .exports = std.ArrayList(Export).init(alloc),
            .elements = std.ArrayList(Element).init(alloc),
            .dataSegments = std.ArrayList(DataSegment).init(alloc),
            .customSections = std.ArrayList(CustomSection).init(alloc),
            .imports = std.ArrayList(Import).init(alloc),
            .tables = std.ArrayList(Table).init(alloc),
            .memory = std.ArrayList(Memory).init(alloc),
            .startFunc = undefined,
            .alloc = alloc,
            .pageAlloc = std.heap.page_allocator,
        };
        const counts_of_things = 64;
        try r.functions.ensureTotalCapacity(counts_of_things);
        try r.globals.ensureTotalCapacity(counts_of_things);
        try r.definitions.ensureTotalCapacity(counts_of_things);
        try r.types.ensureTotalCapacity(counts_of_things);
        try r.exports.ensureTotalCapacity(counts_of_things);
        try r.elements.ensureTotalCapacity(counts_of_things);
        try r.dataSegments.ensureTotalCapacity(counts_of_things);
        try r.customSections.ensureTotalCapacity(counts_of_things);
        try r.imports.ensureTotalCapacity(counts_of_things);
        try r.tables.ensureTotalCapacity(counts_of_things);
        try r.memory.ensureTotalCapacity(counts_of_things);

        return r;
    }

    pub fn deinit(self: *Self) void {
        for (self.functions.items) |i| {
            if (i.code) |c| {
                self.alloc.free(c);
            }
        }
        self.functions.deinit();

        for (self.exports.items) |i| {
            self.alloc.free(i.name);
        }
        self.exports.deinit();

        for (self.imports.items) |i| {
            self.alloc.free(i.moduleName);
            self.alloc.free(i.name);
        }
        self.imports.deinit();

        for (self.types.items) |i| {
            i.params.deinit();
            i.results.deinit();
        }
        self.types.deinit();

        for (self.customSections.items) |i| {
            self.alloc.free(i.name);
        }
        self.customSections.deinit();

        self.memory.deinit();
        self.elements.deinit();
        self.dataSegments.deinit();
        self.globals.deinit();
        return;
    }

    pub fn addFunction(self: *Self, moduleName: []const u8, exportName: []const u8, ptr: u64) !void {
        const def = try self.definitions.addOne();
        def.* = .{
            .moduleName = moduleName,
            .exportName = exportName,
            .fnptr = @ptrFromInt(ptr),
        };
        return;
    }

    fn _addFunction(self: *Self, sigidx: u32) !usize {
        var v = try self.functions.addOne();
        v.funcType = &self.types.items[sigidx];
        v.code = null;
        v.locals = std.ArrayList(Value).init(self.alloc);
        try v.locals.ensureTotalCapacity(32);
        v.index = @intCast(self.functions.items.len - 1);
        return v.index;
    }

    pub fn parseWasm(self: *Self, wasm: []const u8) !void {
        var cursor: usize = 0;

        // Header
        const header = .{ 0x00, 0x61, 0x73, 0x6d };
        if (!std.mem.startsWith(u8, wasm, &header)) {
            return error.NotWasm;
        }
        cursor += 4;

        //const version = std.mem.readVarInt(u32, wasm[cursor .. cursor + 4], .little);
        var stream = std.io.fixedBufferStream(wasm);
        try stream.seekTo(cursor);
        const reader = stream.reader();
        const version = try reader.readInt(u32, .little);

        debugprint("WASM blob version {}\n", .{version});

        while ((try reader.context.getPos()) < wasm.len) {
            const startCursor = try reader.context.getPos();

            const id = try reader.readByte();
            const payloadLen = try std.leb.readULEB128(u32, reader);

            debugprint("Section @0x{x}: {any} ({}) - 0x{x} bytes\n", .{
                startCursor,
                @as(Section, @enumFromInt(id)),
                id,
                payloadLen,
            });

            if (cursor + payloadLen > wasm.len) {
                debugprint("cursor=0x{x} payloadLen=0x{x} wasm.len=0x{x}\n", .{ cursor, payloadLen, wasm.len });
                return error.UnexpectedEof;
            }

            cursor = try reader.context.getPos();
            const payload = wasm[cursor .. cursor + payloadLen];
            try reader.context.seekBy(payloadLen);

            var payloadStream = std.io.fixedBufferStream(payload);
            const payloadReader = payloadStream.reader();

            switch (@as(Section, @enumFromInt(id))) {
                // Parse Type section
                Section.Type => {
                    const numTypes = try std.leb.readULEB128(u32, payloadReader);
                    debugprint("\t{} function types\n", .{numTypes});
                    for (0..numTypes) |_| {
                        const parse = try self.parseFunctionSignature(payloadReader);
                        const v = try self.types.addOne();
                        v.* = parse;
                    }
                },

                Section.Import => {
                    // Parse import section if needed
                    const numImports = try std.leb.readULEB128(u32, payloadReader);
                    debugprint("\t{} imports\n", .{numImports});
                    for (0..numImports) |_| {
                        const moduleNameLen = try std.leb.readULEB128(u32, payloadReader);
                        const moduleName = try self.alloc.alloc(u8, moduleNameLen);
                        _ = try payloadReader.read(moduleName);

                        // Parse field name
                        const fieldNameLen = try std.leb.readULEB128(u32, payloadReader);
                        const fieldName = try self.alloc.alloc(u8, fieldNameLen);
                        _ = try payloadReader.read(fieldName);

                        // Parse import kind
                        const kind = try payloadReader.readByte();

                        switch (@as(ImportKind, @enumFromInt(kind))) {
                            ImportKind.Function => {
                                const signatureIdx = try std.leb.readULEB128(u32, payloadReader);
                                const newidx = try self._addFunction(signatureIdx);
                                self.functions.items[newidx].lookupType = .Import;
                                // import functions are always the first ones in modules
                                debugprint("\tFunction ;{}; with signature {} from import {s}.{s}\n", .{
                                    newidx,
                                    signatureIdx,
                                    moduleName,
                                    fieldName,
                                });
                            },
                            .Table => {
                                @panic("table import\n");
                            },
                            .Memory => {
                                const hasMaximum = (try payloadReader.readByte() == 1);
                                const initial = try std.leb.readULEB128(u32, payloadReader);
                                var maximum: ?u32 = null;
                                if (hasMaximum) {
                                    maximum = try std.leb.readULEB128(u32, payloadReader);
                                }

                                debugprint("\tMemory import from {s}.{s}, initial: {}, max: {any}\n", .{
                                    moduleName,
                                    fieldName,
                                    initial,
                                    maximum,
                                });

                                const size = 1024 * 64 * initial;
                                const mapping = try self.pageAlloc.alloc(u8, size);
                                @memset(mapping, 0);
                                const mem = try self.memory.addOne();
                                mem.* = Memory{
                                    .limits = .{ .initial = initial, .maximum = maximum },
                                    .pageCount = initial,
                                    .mapping = @intFromPtr(mapping.ptr),
                                };
                            },
                            .Global => {
                                @panic("global import\n");
                            },
                        }

                        try self.imports.append(Import{
                            .moduleName = moduleName,
                            .name = fieldName,
                            .kind = .Function,
                        });
                    }
                },

                Section.Function => {
                    // Parse function section if needed
                    const count = try std.leb.readULEB128(u32, payloadReader);
                    for (0..count) |_| {
                        const sigidx = try std.leb.readULEB128(u32, payloadReader);
                        const newidx = try self._addFunction(sigidx);
                        self.functions.items[newidx].lookupType = .Module;
                        debugprint("\tFunction ;{}; with signature {}\n", .{ newidx, sigidx });
                    }
                },

                // Parse Table section
                Section.Table => {
                    const count = try std.leb.readULEB128(u32, payloadReader);

                    for (0..count) |_| {
                        const elementType = @as(ValType, @enumFromInt(try payloadReader.readByte()));
                        const hasMaximum = (try payloadReader.readByte() == 1);
                        const initial = try std.leb.readULEB128(u32, payloadReader);
                        var maximum: ?u32 = null;
                        if (hasMaximum) {
                            maximum = try std.leb.readULEB128(u32, payloadReader);
                        }

                        debugprint("\t{s} initial: {}, max: {any}\n", .{ @tagName(elementType), initial, maximum });

                        const table = try self.tables.addOne();
                        table.* = .{
                            .elementType = elementType,
                            .limits = .{ .initial = initial, .maximum = maximum },
                        };
                    }
                },

                Section.Memory => {
                    const count = try std.leb.readULEB128(u32, payloadReader);

                    for (0..count) |_| {
                        const hasMaximum = (try payloadReader.readByte() == 1);
                        const initial = try std.leb.readULEB128(u32, payloadReader);
                        var maximum: ?u32 = null;
                        if (hasMaximum) {
                            maximum = try std.leb.readULEB128(u32, payloadReader);
                        }

                        debugprint("\tinitial: {}, max: {any}\n", .{ initial, maximum });

                        const size = 1024 * 64 * initial;
                        const mapping = try self.pageAlloc.alloc(u8, size);
                        @memset(mapping, 0);
                        const mem = try self.memory.addOne();
                        mem.* = Memory{
                            .limits = .{ .initial = initial, .maximum = maximum },
                            .pageCount = initial,
                            .mapping = @intFromPtr(mapping.ptr),
                        };
                    }
                },

                // Parse Global section
                Section.Global => {
                    const numGlobals = try std.leb.readULEB128(u32, payloadReader);

                    for (0..numGlobals) |_| {
                        const t = try payloadReader.readByte();
                        const typ = @as(ValType, @enumFromInt(t));
                        const mutable = (try payloadReader.readByte() == 1);
                        const initialValue: u64 = switch (typ) {
                            ValType.externref, ValType.funcref, ValType.functype, ValType.V128 => {
                                return error.BadExternRef;
                            },
                            ValType.F32, ValType.I32 => try std.leb.readULEB128(u32, payloadReader),
                            ValType.F64, ValType.I64 => try std.leb.readULEB128(u64, payloadReader),
                            else => try std.leb.readULEB128(u64, payloadReader),
                        };

                        debugprint("\t{s}{any} = {}\n", .{ if (mutable) "" else "const ", typ, initialValue });

                        try self.globals.append(.{
                            .t = typ,
                            .mutable = mutable,
                            .v = initialValue,
                        });
                    }
                },

                // Parse Export section
                Section.Export => {
                    const numExports = try std.leb.readULEB128(u32, payloadReader);

                    for (0..numExports) |_| {
                        const nameLen = try std.leb.readULEB128(u32, payloadReader);
                        const name = try self.alloc.alloc(u8, nameLen);
                        _ = try payloadReader.read(name);
                        const kind = @as(ExportKind, @enumFromInt(try payloadReader.readByte()));
                        const index = try std.leb.readULEB128(u32, payloadReader);

                        debugprint("\tExport: \"{s}\", index: {}, kind: {s}\n", .{ name, index, @tagName(kind) });

                        try self.exports.append(.{
                            .name = name,
                            .kind = kind,
                            .index = index,
                        });
                    }
                },

                Section.Start => {
                    if (try payloadReader.context.getEndPos() != 4) {
                        return error.InvalidStartSectionPayloadLength;
                    }
                    self.startFunc = try std.leb.readULEB128(u32, payloadReader);
                },

                Section.Element => {
                    debugprint("Skipping Element section for now!\n", .{});
                },

                Section.Data => {
                    // Parse memory index
                    const memoryIndex = try std.leb.readULEB128(u32, payloadReader);

                    const offsetOp = try payloadReader.readByte();

                    const offset = try std.leb.readULEB128(u32, payloadReader);

                    // Parse data bytes
                    const dataLen = try std.leb.readULEB128(u32, payloadReader);
                    const data = try self.alloc.alloc(u8, dataLen);
                    _ = try payloadReader.read(data);

                    debugprint("Data at 0x{x} offset 0x{x} (op={}) -- {} bytes\n", .{
                        memoryIndex,
                        offset,
                        offsetOp,
                        dataLen,
                    });

                    // Handle data here
                    try self.dataSegments.append(DataSegment{
                        .data = data,
                        .memoryIndex = memoryIndex,
                        .offset = offset,
                    });
                },
                Section.DataCount => {
                    return error.Todo;
                },

                Section.Custom => {
                    // Parse section name length
                    const nameLen = try std.leb.readULEB128(u32, payloadReader);
                    // Parse section name
                    const name = try self.alloc.alloc(u8, nameLen);
                    _ = try payloadReader.read(name);
                    // Parse custom payload
                    const payloadLen2 = try std.leb.readULEB128(u32, payloadReader);
                    const customPayload = try self.alloc.alloc(u8, payloadLen2);
                    _ = try payloadReader.read(customPayload);

                    // Handle custom section here
                    try self.customSections.append(.{
                        .name = name,
                        .payload = customPayload,
                    });
                },

                // Parse Code section
                Section.Code => {
                    const numFuncs = try std.leb.readULEB128(u32, payloadReader);

                    for (0..numFuncs) |curFunc| {
                        const funcIdx = self.getImportFunctionCount() + curFunc;
                        const func: *Function = &self.functions.items[funcIdx];
                        var codeLen = try std.leb.readULEB128(u32, payloadReader);
                        const startIdx = try payloadReader.context.getPos();
                        var numLocals = try std.leb.readULEB128(u32, payloadReader);

                        debugprint("\tfunc ;{}; size {}\n", .{ funcIdx, codeLen });
                        debugprint("\t{} locals\n", .{numLocals});
                        while (numLocals > 0) {
                            const numLocalsOfThisType = try std.leb.readULEB128(u32, payloadReader);
                            debugprint("\ttype count={}", .{numLocalsOfThisType});
                            const valueType = try std.leb.readULEB128(u32, payloadReader);
                            const vtype = @as(ValType, @enumFromInt(valueType));
                            debugprint("type={s}\n", .{@tagName(vtype)});
                            for (0..numLocalsOfThisType) |_| {
                                try func.locals.append(Value{
                                    .t = vtype,
                                    .v = 0,
                                    .mutable = true,
                                });
                            }
                            numLocals -= 1;
                        }

                        codeLen = codeLen - @as(u32, @intCast(try payloadReader.context.getPos() - startIdx));

                        debugprint("Code length is {} instructions\n", .{codeLen});
                        debugprint("remaining length is {}\n", .{try payloadReader.context.getEndPos() - try payloadReader.context.getPos()});

                        const code = try self.alloc.alloc(u8, codeLen);

                        const count = payloadReader.read(code) catch |e| {
                            debugprint("Exception with read: {}\n", .{e});
                            const code2 = try payloadReader.readAllAlloc(self.alloc, 10000000);
                            dump_hex(code2);
                            return error.ParseFunction;
                        };
                        if (count != code.len) {
                            debugprint("Could not read all of code\n", .{});
                            const code2 = try payloadReader.readAllAlloc(self.alloc, 10000000);
                            dump_hex(code2);
                            return error.ParseFunction;
                        }
                        debugprint("Read code\n", .{});

                        func.code = code;
                        debugprint("\tAdded new Code for function {}\n", .{funcIdx});
                    }
                },
            }
        }

        debugprint("Done with parsing loop\n", .{});

        return;
    }

    fn getImportFunctionCount(self: *Self) usize {
        var count: usize = 0;
        for (self.functions.items) |f| {
            debugprint("{any}\n", .{f});
            if (f.lookupType == .Import) {
                count += 1;
            }
        }
        debugprint("{} import functions; {} total functions\n", .{ count, self.functions.items.len });
        return count;
    }

    // Parse a WebAssembly function type

    fn parseFunctionSignature(self: *Self, reader: anytype) !FunctionSignature {
        const funcType = try reader.readByte();
        if (funcType != @intFromEnum(ValType.functype)) {
            return error.NotAFunction;
        }

        const cur = self.types.items.len;

        // Parse the function type
        const numParams = try std.leb.readULEB128(u32, reader);
        debugprint("\tindex: {} = params [ ", .{cur});

        var params = std.ArrayList(ValType).init(self.alloc);
        for (0..numParams) |_| {
            const valueType = @as(ValType, (@enumFromInt(try reader.readByte())));
            debugprint("{s} ", .{@tagName(valueType)});
            try params.append(valueType);
        }
        debugprint("]", .{});

        const numResults = try std.leb.readULEB128(u32, reader);

        debugprint(" -> [ ", .{});

        var results = std.ArrayList(ValType).init(self.alloc);
        for (0..numResults) |_| {
            const valueType = @as(ValType, (@enumFromInt(try reader.readByte())));
            debugprint("{s} ", .{@tagName(valueType)});
            try results.append(valueType);
        }
        debugprint("]\n", .{});

        return .{
            .params = params,
            .results = results,
        };
    }

    pub fn printModuleInfo(self: Self) void {
        // Print some information about the parsed module
        debugprint("WebAssembly module information:\n", .{});

        // Print function types
        debugprint("Function types:\n", .{});
        for (self.types.items) |t| {
            debugprint("  Params: ", .{});
            for (t.params.items) |param| {
                debugprint("{s} ", .{@tagName(param)});
            }
            debugprint("\n", .{});
            debugprint("  Results: ", .{});
            for (t.results.items) |result| {
                debugprint("{s} ", .{@tagName(result)});
            }
            debugprint("\n\n", .{});
        }

        // Print functions
        debugprint("Functions:\n", .{});
        for (self.functions.items, 0..) |func, i| {
            debugprint("  Index: {}\n", .{i});
            debugprint("  Locals: ", .{});
            if (func.locals) |l| {
                for (l.items) |local| {
                    debugprint("{any} ", .{local});
                }
            }
            debugprint("\n\n", .{});
        }

        // Print table info if present
        for (self.tables.items, 0..) |table, i| {
            debugprint("Table {}:\n", .{i});
            debugprint("  Element Type: {s}\n", .{@tagName(table.elementType)});
            debugprint("  Initial: {any}\n", .{table.limits.initial});
            if (table.limits.maximum != null) {
                debugprint("  Maximum: {any}\n", .{table.limits.maximum});
            } else {
                debugprint("  Maximum: Unbounded\n", .{});
            }
        }

        // Print memory info if present
        for (self.memory.items, 0..) |memory, i| {
            debugprint("Memory {}:\n", .{i});
            debugprint("  Initial: {any}\n", .{memory.limits.initial});
            if (memory.limits.maximum != null) {
                debugprint("  Maximum: {any}\n", .{memory.limits.maximum});
            } else {
                debugprint("  Maximum: Unbounded\n", .{});
            }
        }

        // Print global variables if present
        debugprint("Globals:\n", .{});
        for (self.globals.items) |global| {
            debugprint("  Type: {s}\n", .{@tagName(global.type)});
            debugprint("  Mutable: {any}\n", .{global.mutable});
            debugprint("  Initial Value: {any}\n", .{global.initialValue});
        }

        // Print exports if present
        debugprint("Exports:\n", .{});
        for (self.exports.items) |ex| {
            debugprint("  Name: {s}\n", .{ex.name});
            debugprint("  Kind: {s}\n", .{@tagName(ex.kind)});
            debugprint("  Index: {any}\n", .{ex.index});
        }

        // Print start function if present
        if (self.startFunc != null) {
            debugprint("Start Function: {any}\n", .{self.startFunc});
        }

        // Print elements if present
        // ...

        // Print data segments if present
        // ...

        // Print custom sections if present
        // ...
    }
};

// Define the structure of a WebAssembly function type
const FunctionSignature = struct {
    params: std.ArrayList(ValType),
    results: std.ArrayList(ValType),

    pub fn format(sig: FunctionSignature, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.writeAll("FunctionSignature{[");

        for (sig.params.items, 0..) |p, i| {
            if (i != 0) {
                try writer.writeAll(" ");
            }
            _ = try writer.print("{s}", .{@tagName(p)});
        }
        try writer.writeAll("] -> [");

        for (sig.results.items, 0..) |r, i| {
            if (i != 0) {
                try writer.writeAll(" ");
            }
            _ = try writer.print("{s}", .{@tagName(r)});
        }
        try writer.writeAll("]}");
    }
};

const FunctionLookupType = enum {
    Import,
    Module,
};

const MemoryOperand = struct {
    offset: u32,
    alignment: u32,
};

// Define the structure of a WebAssembly function
const Function = struct {
    funcType: *FunctionSignature,
    locals: std.ArrayList(Value),
    code: ?[]const u8,
    lookupType: FunctionLookupType,
    index: u32,

    pub fn format(self: Function, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        _ = try writer.print("{s} function ;{};", .{ @tagName(self.lookupType), self.index });
        _ = try writer.print("{any}", .{self.funcType});
        _ = try writer.print(" code={any}", .{self.code});
    }
};

const Import = struct {
    moduleName: []const u8,
    name: []const u8,
    kind: ImportKind,
};

// Define the structure of a WebAssembly table
const Table = struct {
    elementType: ValType,
    limits: struct {
        initial: u32,
        maximum: ?u32,
    },
};

// Define the structure of a WebAssembly memory
const Memory = struct {
    limits: struct {
        initial: u32,
        maximum: ?u32,
    },
    pageCount: u32,
    mapping: u64,
};

// Define the structure of a global variable
const Global = Value;

// Define the structure of an export
const Export = struct {
    name: []const u8,
    kind: ExportKind,
    index: u32,
};

// Define the structure of an element
const Element = struct {
    tableIndex: u32,
    offset: u32,
    functionIndices: []u32,
};

const ExportKind = enum {
    Function,
    Table,
    Memory,
    Global,
};

const ImportKind = enum(u8) {
    Function = 0,
    Table = 1,
    Memory = 2,
    Global = 3,
};

// Define the structure of a data segment
const DataSegment = struct {
    memoryIndex: u32,
    offset: u32,
    data: []const u8,
};

// Define the structure of a custom section
const CustomSection = struct {
    name: []const u8,
    payload: []const u8,
};

const WasmFunctionPtr = *const fn (*Wasm) void;

const FunctionDefinition = struct {
    moduleName: []const u8,
    exportName: []const u8,
    fnptr: WasmFunctionPtr,
};

const Block = struct {
    id: u64,
    skip: bool = false,
};

pub const Wasm = struct {
    module: *Module,
    alloc: std.mem.Allocator,
    stack: std.ArrayList(Value),
    blocks: std.ArrayList(Block),
    ip: u32,

    const Self = @This();

    pub fn init(alloc: std.mem.Allocator, module: *Module) Self {
        return .{
            .alloc = alloc,
            .module = module,
            .stack = std.ArrayList(Value).init(alloc),
            .blocks = std.ArrayList(Block).init(alloc),
            .ip = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.stack.deinit();
    }

    fn readMemoryOperand(self: *Self, reader: anytype) !MemoryOperand {
        const alignment: u32 = @intCast(try self.readOperandValue(reader));
        const offset: u32 = @intCast(try self.readOperandValue(reader));
        return MemoryOperand{
            .alignment = alignment,
            .offset = offset,
        };
    }

    fn lookupFunction(self: Self, moduleName: []const u8, exportName: []const u8) !WasmFunctionPtr {
        for (self.module.definitions.items) |def| {
            if (std.mem.eql(u8, def.moduleName, moduleName) and std.mem.eql(u8, def.exportName, exportName)) {
                return def.fnptr;
            }
        }
        return error.NotFound;
    }

    pub fn run(self: *Self) !void {
        var function: ?*Function = null;

        try self.stack.ensureTotalCapacity(128);

        if (self.module.startFunc) |s| {
            function = &self.module.functions.items[s];
            debugprint("Set start function to ;{}; {}\n", .{ s, function.? });
        }

        for (self.module.exports.items) |sym| {
            if (std.mem.eql(u8, "_start", sym.name) and sym.kind == .Function) {
                function = &self.module.functions.items[sym.index];
                debugprint("Set start function to ;{}; {}\n", .{ sym.index, function.? });
            }
        }

        if (function) |f| {
            try self.executeFunction(f);
        } else {
            @panic("no start func");
        }

        return;
    }

    fn readOperandValue(self: *Self, reader: anytype) !u64 {
        const cur = @as(u32, @intCast(try reader.context.getPos()));
        const value = try std.leb.readULEB128(u64, reader);
        self.ip += @intCast(try reader.context.getPos() - cur);
        return value;
    }

    pub fn pushValue(self: *Self, value: Value) !void {
        const val = try self.stack.addOne();
        val.* = value;
        return;
    }

    pub fn popValue(self: *Self) Value {
        return self.stack.pop();
    }

    fn executeInstruction(self: *Self, reader: anytype, function: *Function, op: std.wasm.Opcode) anyerror!void {
        switch (op) {
            .@"unreachable" => {
                unreachable;
            },
            .nop => {
                return;
            },
            .block => {
                const id = try self.readOperandValue(reader);
                debugprint(" id @{}\n", .{id});
                const blk = try self.blocks.addOne();
                blk.id = id;
                blk.skip = false;
            },
            .call => {
                const funcId = try self.readOperandValue(reader);
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                debugprint(" function ;{};\n", .{funcId});
                try self.executeFunction(&self.module.functions.items[funcId]);
            },
            .local_get => {
                const id = try self.readOperandValue(reader);
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                debugprint(" id {}", .{id});
                try self.pushValue(Value{
                    .t = function.locals.items[id].t,
                    .v = function.locals.items[id].v,
                    .mutable = true,
                });
            },
            .local_set => {
                const id = try self.readOperandValue(reader);
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                const value = self.popValue();
                debugprint("[{}] = {any}", .{ id, value });
                function.locals.items[id] = value;
            },
            .local_tee => {
                const id = try self.readOperandValue(reader);
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                const value = self.popValue();
                debugprint("[{}] = {any}", .{ id, value });
                try self.pushValue(value);
                function.locals.items[id] = value;
            },
            .global_get => {
                const globalId = try self.readOperandValue(reader);
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                debugprint(" global[{}] = {}\n", .{
                    globalId,
                    self.module.globals.items[globalId],
                });
                try self.pushValue(self.module.globals.items[globalId]);
            },
            .global_set => {
                const globalId = try self.readOperandValue(reader);
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                const value = self.popValue();
                debugprint(" global[{}] = {}\n", .{ globalId, value });
                self.module.globals.items[globalId] = value;
            },
            .i32_store => {
                const m = try self.readMemoryOperand(reader);
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                const p = @as(*u32, @ptrFromInt(self.module.memory.items[0].mapping + m.offset));
                const value = self.popValue();
                debugprint(" offset=0x{x} align=0x{x} value=0x{x}\n", .{
                    m.offset,
                    m.alignment,
                    value,
                });
                p.* = @as(u32, @intCast(value.v & 0xffffffff));
            },
            .i32_store8 => {
                const m = try self.readMemoryOperand(reader);
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                const p = @as(*u8, @ptrFromInt(self.module.memory.items[0].mapping + m.offset));
                const value = self.popValue();
                debugprint(" offset=0x{x} align=0x{x} value=0x{x}\n", .{
                    m.offset,
                    m.alignment,
                    value,
                });
                p.* = @as(u8, @intCast(value.v & 0xff));
            },
            .i64_load => {
                const m = try self.readMemoryOperand(reader);
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                const p = @as(*u64, @ptrFromInt(self.module.memory.items[0].mapping + m.offset));
                debugprint(" offset=0x{x} align=0x{x} value=0x{x}\n", .{
                    m.offset,
                    m.alignment,
                    p.*,
                });
                try self.pushValue(.{
                    .mutable = true,
                    .t = .I64,
                    .v = p.*,
                });
            },
            .i32_load => {
                const m = try self.readMemoryOperand(reader);
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                const p = @as(*u32, @ptrFromInt(self.module.memory.items[0].mapping + m.offset));
                debugprint(" offset=0x{x} align=0x{x} value=0x{x}\n", .{
                    m.offset,
                    m.alignment,
                    p.*,
                });
                try self.pushValue(.{
                    .mutable = true,
                    .t = .I64,
                    .v = p.*,
                });
            },
            .i32_load8_u => {
                const m = try self.readMemoryOperand(reader);
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                const p = @as(*u8, @ptrFromInt(self.module.memory.items[0].mapping + m.offset));
                debugprint(" offset=0x{x} align=0x{x} value=0x{x}\n", .{
                    m.offset,
                    m.alignment,
                    p.*,
                });
                try self.pushValue(.{
                    .mutable = true,
                    .t = .I64,
                    .v = p.*,
                });
            },
            .i32_const => {
                const val = try self.readOperandValue(reader);
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                debugprint(" {} (0x{x})", .{ val, val });
                try self.pushValue(.{
                    .mutable = true,
                    .t = .I32,
                    .v = val,
                });
            },
            .i64_const => {
                const val = try self.readOperandValue(reader);
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                debugprint(" {} (0x{x})", .{ val, val });
                try self.pushValue(.{
                    .mutable = true,
                    .t = .I64,
                    .v = val,
                });
            },
            .i32_add => {
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                const two: i32 = @intCast(self.popValue().v);
                const one: i32 = @intCast(self.popValue().v);
                debugprint(" {} + {} = {}", .{ one, two, one + two });
                try self.pushValue(Value{
                    .mutable = true,
                    .t = .I32,
                    .v = @intCast(one + two),
                });
            },
            .i32_sub => {
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                const two: i32 = @intCast(self.popValue().v);
                const one: i32 = @intCast(self.popValue().v);
                debugprint(" {} - {} = {}", .{ one, two, one - two });
                try self.pushValue(Value{
                    .mutable = true,
                    .t = .I32,
                    .v = @intCast(one - two),
                });
            },
            .i32_mul => {
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                const two: i32 = @intCast(self.popValue().v);
                const one: i32 = @intCast(self.popValue().v);
                debugprint(" {} * {} = {}", .{ one, two, @as(i32, @intCast(one * two)) });
                try self.pushValue(Value{
                    .mutable = true,
                    .t = .I32,
                    .v = @intCast(one * two),
                });
            },
            .i32_and => {
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                const two: i32 = @intCast(self.popValue().v);
                const one: i32 = @intCast(self.popValue().v);
                debugprint(" {} & {} = {}", .{ one, two, @as(i32, @intCast(one & two)) });
                try self.pushValue(Value{
                    .mutable = true,
                    .t = .I32,
                    .v = @intCast(one & two),
                });
            },
            .i32_or => {
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                const two: i32 = @intCast(self.popValue().v);
                const one: i32 = @intCast(self.popValue().v);
                debugprint(" {} | {} = {}", .{ one, two, @as(i32, @intCast(one | two)) });
                try self.pushValue(Value{
                    .mutable = true,
                    .t = .I32,
                    .v = @intCast(one | two),
                });
            },
            .i32_xor => {
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                const two: i32 = @intCast(self.popValue().v);
                const one: i32 = @intCast(self.popValue().v);
                debugprint(" {} ^ {} = {}", .{ one, two, @as(i32, @intCast(one ^ two)) });
                try self.pushValue(Value{
                    .mutable = true,
                    .t = .I32,
                    .v = @intCast(one ^ two),
                });
            },
            .i32_shl => {
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                const two: u5 = @intCast(self.popValue().v);
                const one: i32 = @intCast(self.popValue().v);
                debugprint(" {} << {} = {}", .{ one, two, @as(i32, @intCast(one << two)) });
                try self.pushValue(Value{
                    .mutable = true,
                    .t = .I32,
                    .v = @intCast(one << two),
                });
            },
            .i32_shr_s => {
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                const two: u5 = @intCast(self.popValue().v);
                const one: i32 = @intCast(self.popValue().v);
                debugprint(" {} >> {} = {}", .{ one, two, @as(i32, @intCast(one >> two)) });
                try self.pushValue(Value{
                    .mutable = true,
                    .t = .I32,
                    .v = @intCast(one >> two),
                });
            },
            .i32_shr_u => {
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                const two: u5 = @intCast(self.popValue().v);
                const one: i32 = @intCast(self.popValue().v);
                debugprint(" {} >> {} = {}", .{ one, two, @as(i32, @intCast(one >> two)) });
                try self.pushValue(Value{
                    .mutable = true,
                    .t = .I32,
                    .v = @intCast(one >> two),
                });
            },
            .br_if => {
                const labelidx: u32 = @intCast(try self.readOperandValue(reader));
                if (!self.shouldExecuteInstruction()) {
                    return;
                }
                const c: i32 = @intCast(self.popValue().v);
                debugprint(" {} ", .{c});
                if (c == 0) {
                    debugprint(" br {}\n", .{labelidx});
                    self.blocks.items[self.blocks.items.len - 1].skip = true;
                } else {
                    debugprint(" no branch\n", .{});
                }
            },
            .end => {
                debugprint(" block\n", .{});
                if (self.blocks.popOrNull() == null) {
                    debugprint("done\n", .{});
                }
            },
            else => {
                debugprint("\ninstruction unimplemented: {s}\n", .{@tagName(op)});
                @panic("unknown instruction");
            },
        }
    }

    fn shouldExecuteInstruction(self: *Self) bool {
        if (self.blocks.items.len == 0) {
            return true;
        }
        return !self.blocks.items[self.blocks.items.len - 1].skip;
    }

    fn executeFunction(self: *Self, function: *Function) !void {
        switch (function.lookupType) {
            FunctionLookupType.Import => {
                const imp = self.module.imports.items[function.index];
                const f = try self.lookupFunction(imp.moduleName, imp.name);

                debugprint("{s} {any} at 0x{x}\n", .{ @src().fn_name, function, f });

                const CallType = *const fn (*Wasm) void;
                const fcall = @as(CallType, f);
                fcall(self);

                debugprint("After function called\n", .{});
            },
            FunctionLookupType.Module => {
                if (function.code) |code| {
                    var stream = std.io.fixedBufferStream(code);
                    var reader = stream.reader();
                    self.ip = 0;
                    while (self.ip < try stream.getEndPos()) {
                        debugprint("{} {}\n", .{ self.ip, try stream.getEndPos() });
                        const op = @as(std.wasm.Opcode, @enumFromInt(try reader.readByte()));
                        self.ip += 1;
                        debugprint("0x{x}: {s}", .{ self.ip, @tagName(op) });
                        try self.executeInstruction(reader, function, op);
                        debugprint("\n", .{});
                    }
                }
            },
        }
    }
};
