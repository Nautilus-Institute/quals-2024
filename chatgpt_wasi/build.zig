const std = @import("std");

const targets: []const std.Target.Query = &.{
    .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl },
};

pub fn build(b: *std.Build) void {
    for (targets) |t| {
        const exe = b.addExecutable(.{
            .name = "defcon-wasi",
            .root_source_file = .{ .path = "src/main.zig" },
            .target = b.resolveTargetQuery(t),
            .optimize = .ReleaseSmall,
            .single_threaded = true,
            .strip = true,
            .link_libc = true,
        });

        const target_output = b.addInstallArtifact(exe, .{
            .dest_dir = .{
                .override = .{
                    .custom = "../bin/",
                },
            },
        });
        b.getInstallStep().dependOn(&target_output.step);
    }
}
