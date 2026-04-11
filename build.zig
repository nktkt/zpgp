const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zpgp_mod = b.addModule("zpgp", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "zpgp",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zpgp", .module = zpgp_mod },
            },
        }),
    });
    b.installArtifact(exe);

    // --- C shared library (libzpgp) ---
    // Uses root.zig as the module root so the cabi module can access
    // all zpgp sub-modules. The `export` functions in cabi/zpgp.zig
    // are automatically exported as C symbols.
    const lib = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "zpgp",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(lib);

    // --- C static library (libzpgp_static) ---
    const static_lib = b.addLibrary(.{
        .linkage = .static,
        .name = "zpgp_static",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(static_lib);

    const run_step = b.step("run", "Run the zpgp CLI");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const mod_tests = b.addTest(.{
        .root_module = zpgp_mod,
    });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);

    // --- WASM build target ---
    //
    // Cross-compiles zpgp to wasm32-freestanding for use in browsers
    // and other WASM runtimes. The entry point is src/wasm/exports.zig
    // which re-exports key functions with WASM-compatible interfaces.
    //
    // Build: zig build wasm
    // Output: zig-out/lib/zpgp.wasm
    const wasm_target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
    });

    const wasm_lib = b.addLibrary(.{
        .linkage = .static,
        .name = "zpgp",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/wasm/exports.zig"),
            .target = wasm_target,
            .optimize = .ReleaseSmall,
        }),
    });

    const wasm_install = b.addInstallArtifact(wasm_lib, .{});
    const wasm_step = b.step("wasm", "Build WASM library (wasm32-freestanding)");
    wasm_step.dependOn(&wasm_install.step);
}
