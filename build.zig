const std = @import("std");

const c_sources: []const []const u8 = &.{
    "main.c",
};

const cflags: []const []const u8 = &.{
    "-std=c23",
    "-Weverything",
    "-Wno-gnu-alignof-expression",
    "-Wno-strict-prototypes",
    "-Wno-declaration-after-statement",
    "-Wno-padded",
    "-Wno-reserved-macro-identifier",
    "-Wno-unsafe-buffer-usage",
    "-Wno-reserved-identifier",
    "-Wno-covered-switch-default",
    "-Wno-class-varargs",
    "-Wno-pre-c23-compat",
    "-Wno-pre-c11-compat",
    "-Wno-cast-qual",
    "-Wno-disabled-macro-expansion",
    "-Wno-unknown-warning-option",
    "-Wno-used-but-marked-unused",
    "-Werror",
    "-gsplit-dwarf",
};

const min_x64_cpu_model = std.Target.Query.CpuModel{ .explicit = &std.Target.x86.cpu.tigerlake };

const targets: []const std.Target.Query = &.{
    .{ .cpu_arch = .x86_64, .os_tag = .macos },
    .{ .cpu_arch = .aarch64, .os_tag = .macos },
    .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .musl },
    .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu, .cpu_model = min_x64_cpu_model },
    .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl, .cpu_model = min_x64_cpu_model },
    .{ .cpu_arch = .x86_64, .os_tag = .windows, .cpu_model = min_x64_cpu_model },
};

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    //const defaultTarget = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    for (targets) |t| {
        const target = b.resolveTargetQuery(t);

        const exe = b.addExecutable(.{
            .name = "torrent",
            .target = target,
            .optimize = optimize,
            .pic = true,
            .omit_frame_pointer = false,
            .unwind_tables = false,
        });

        exe.addCSourceFiles(.{
            .files = c_sources,
            .flags = cflags,
        });

        const libuv_dep = b.dependency("libuv", .{
            .target = target,
            .optimize = optimize,
        });
        exe.link_data_sections = true;
        exe.link_function_sections = true;
        exe.link_gc_sections = true;
        exe.linkLibrary(libuv_dep.artifact("uv"));
        exe.linkLibC();

        const target_output = b.addInstallArtifact(exe, .{
            .dest_dir = .{
                .override = .{
                    .custom = t.zigTriple(b.allocator) catch @panic("invalid zig triple"),
                },
            },
        });

        b.getInstallStep().dependOn(&target_output.step);
    }

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    //const run_cmd = b.addRunArtifact(exe);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    //    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    // if (b.args) |args| {
    //     run_cmd.addArgs(args);
    // }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    // const run_step = b.step("run", "Run the app");
    // run_step.dependOn(&run_cmd.step);
}
