const std = @import("std");
const libwasm = @import("wasm.zig");
const Wasm = libwasm.Wasm;
const Module = libwasm.Module;

pub fn cat_flag() !void {
    var file = try std.fs.cwd().openFile("/flag", .{});
    defer file.close();

    var buf_reader = std.io.bufferedReader(file.reader());
    var in_stream = buf_reader.reader();

    var buf: [1024]u8 = undefined;
    while (try in_stream.readUntilDelimiterOrEof(&buf, '\n')) |line| {
        std.debug.print("{s}", .{line});
    }
    return;
}

pub fn print_number(wasm: *Wasm) void {
    const one: u64 = wasm.popValue().v;
    std.debug.print("{x}\n", .{one});
}

pub fn check_variable(wasm: *Wasm) void {
    const two: u64 = wasm.popValue().v;
    const one: u64 = wasm.popValue().v;
    std.debug.print("check_numbers\n", .{});
    var file = std.fs.cwd().openFile("/dev/urandom", .{}) catch |e| {
        std.debug.print("{any}", .{e});
        return;
    };
    defer file.close();

    var buffer: [@sizeOf(u64) * 2]u8 = undefined;
    _ = file.readAll(&buffer) catch |e| {
        std.debug.print("{any}", .{e});
        return;
    };

    const testone: *const u64 = @as(*u64, @alignCast(@ptrCast(&buffer[0])));
    const testtwo: *const u64 = @as(*u64, @alignCast(@ptrCast(&buffer[@sizeOf(u64)])));

    std.debug.print("guesses: {} {}\n", .{ one, two });
    std.debug.print("results: {} {}\n", .{ testone.*, testtwo.* });

    if (testone.* == one and testtwo.* == two) {
        @call(.never_inline, cat_flag, .{}) catch |err| {
            std.debug.print("This really should not happen? {any}\n", .{err});
        };
        return;
    }
    std.debug.print("nah\n", .{});
    return;
}

pub fn write_wrapper(wasm: *Wasm) void {
    var val = wasm.popValue();
    const flags: u32 = @intCast(val.v);
    val = wasm.popValue();
    const count: u32 = @intCast(val.v);
    val = wasm.popValue();
    const addr: u32 = @intCast(val.v);
    val = wasm.popValue();
    const fd: u32 = @intCast(val.v);

    const ret: i32 = -1;
    std.debug.print("{s} ({}, {}, {}, {}) ", .{ @src().fn_name, fd, addr, count, flags });
    wasm.pushValue(libwasm.Value{
        .t = .I32,
        .v = @bitCast(@as(i64, ret)),
        .mutable = true,
    }) catch |e| {
        std.debug.print("Could not push return value: {any}\n", .{e});
    };
    @panic("write called");
    //return;
}
pub fn exit_wrapper(wasm: Wasm, err: u32) void {
    _ = wasm;
    std.posix.exit(@intCast(err));
}

pub fn main() !void {
    var buffer: [4096 * 256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const alloc = fba.allocator();

    _ = std.c.alarm(30);
    _ = std.c.dup2(1, 2);

    std.debug.print("Give wasm plz:\n", .{});

    var buf: [65535]u8 = undefined;
    var size: u16 = 0;
    var count = try std.posix.read(0, std.mem.asBytes(&size));
    size = std.mem.bigToNative(@TypeOf(size), size);
    if (count != @sizeOf(@TypeOf(size))) {
        return;
    }
    std.debug.print("{} bytes plz:\n", .{size});
    count = 0;
    while (count != size) {
        const got = try std.posix.read(0, buf[count..]);
        if (got == 0) {
            return;
        }
        count += got;
    }

    var module = try Module.init(alloc);
    module.parseWasm(buf[0..size]) catch {
        std.debug.print("Error parsing wasm\n", .{});
        std.posix.exit(0);
    };
    defer module.deinit();

    try module.addFunction("env", "check_variable", @intFromPtr(&check_variable));
    try module.addFunction("env", "print_number", @intFromPtr(&print_number));
    try module.addFunction("wasi_snapshot_preview1", "fd_write", @intFromPtr(&write_wrapper));
    try module.addFunction("wasi_snapshot_preview1", "proc_exit", @intFromPtr(&exit_wrapper));

    var wasm = Wasm.init(alloc, &module);
    defer wasm.deinit();

    std.debug.print("Running wasm\n", .{});

    try wasm.run();
    std.posix.exit(0);
}
