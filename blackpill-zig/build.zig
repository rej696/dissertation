const std = @import("std");

const exe_name = "firmware";

const c_src: []const []const u8 = &.{
    "hal/startup.c",
    "main.c",
    "hal/uart.c",
    "hal/gpio.c",
    "hal/systick.c",
    "utils/dbc_assert.c",
};

const c_flags: []const []const u8 = &.{
    "-Wall",
    "-Wextra",
    "-Wundef",
    "-Wshadow",
    "-Wdouble-promotion",
    "-fno-common",
    "-Wconversion",
    "-g3",
    "-Os", // Important!
};

pub fn build(b: *std.Build) void {
    const target = b.resolveTargetQuery(target_default);
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });

    const zig_obj = b.addObject(.{
        .name = "zig_main.o",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = false,
            .single_threaded = true,
            .pic = true,
            .root_source_file = b.path("src/zig/main.zig"),
        })
    });
    zig_obj.addIncludePath(b.path("inc"));

    const exe = b.addExecutable(.{
        .name = exe_name ++ ".elf",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .single_threaded = true,
            .link_libc = false,
        }),
        .linkage = .static,
    });

    exe.addObject(zig_obj);

    // Might not need this for start files
    // setupArmGcc(b, exe);

    // setup linker script
    exe.entry = .{ .symbol_name = "_reset" };
    exe.link_gc_sections = true;
    exe.link_data_sections = true;
    exe.link_function_sections = true;
    exe.setLinkerScript(b.path("stm32f411xx.ld"));

    // program include path
    exe.addIncludePath(b.path("inc"));

    // C source files
    exe.addCSourceFiles(.{
        .root = b.path("src"),
        .files = c_src,
        .flags = c_flags,
    });

    // get bin from elf
    extractBin(b, exe, .bin);
    // get hex from elf
    extractBin(b, exe, .hex);

    b.installArtifact(exe);

    const emu_step = b.addSystemCommand(&[_][]const u8{
        "sh",
        "-c",
        ". venv/bin/activate && python3 -m emu zig-out/bin/firmware.bin",
    });
    b.step("emu", "Run the emulator").dependOn(&emu_step.step);
}

const target_default: std.Target.Query = .{
    .cpu_arch = .thumb,
    .os_tag = .freestanding,
    .abi = .eabi,
    .cpu_model = std.Target.Query.CpuModel{ .explicit = &std.Target.arm.cpu.cortex_m4 },
    .cpu_features_add = std.Target.arm.featureSet(
        &[_]std.Target.arm.Feature{
            std.Target.arm.Feature.vfp4d16sp,
        },
    ),
};

/// ObjCopy an elf to a hex or bin format
fn extractBin(b: *std.Build, exe: *std.Build.Step.Compile, comptime format: std.Build.Step.ObjCopy.RawFormat) void {
    const bin = b.addObjCopy(exe.getEmittedBin(), .{
        .format = format,
    });
    bin.step.dependOn(&exe.step);
    const copy_bin = b.addInstallBinFile(bin.getOutput(), exe_name ++ "." ++ @tagName(format));
    b.default_step.dependOn(&copy_bin.step);
}

/// Find arm-none-eabi-gcc and associated built in libraries and link them into the exe
/// https://github.com/haydenridd/stm32-zig-porting-guide
fn setupArmGcc(b: *std.Build, exe: *std.Build.Step.Compile) void {
    // get the arm gcc compiler
    const arm_gcc = getDepPath(b, "arm-none-eabi-gcc");

    // figure out paths to arm gcc built-in libraries
    const sysroot_path = parseCommand(b, &.{ arm_gcc, "-print-sysroot" });
    const multidir_rel_path = parseCommand(b, &.{
        arm_gcc,
        "-mcpu=cortex-m4",
        "-mfpu=fpv4-sp-d16",
        "-mfloat-abi=hard",
        "-print-multi-directory",
    });
    const version = parseCommand(b, &.{ arm_gcc, "-dumpversion" });
    const lib_path1 = b.fmt("{s}/../lib/gcc/arm-none-eabi/{s}/{s}", .{ sysroot_path, version, multidir_rel_path });
    const lib_path2 = b.fmt("{s}/lib/{s}", .{ sysroot_path, multidir_rel_path });

    // manually add nano version of newlib c (--specs nano.specs -lc -lgcc)
    exe.addLibraryPath(.{ .cwd_relative = lib_path1 });
    exe.addLibraryPath(.{ .cwd_relative = lib_path2 });
    exe.addSystemIncludePath(.{ .cwd_relative = b.fmt("{s}/include", .{sysroot_path}) });
    exe.linkSystemLibrary("c_nano");

    // manually add c runtime objects bundled with arm-gcc
    exe.addObjectFile(.{ .cwd_relative = b.fmt("{s}/crt0.o", .{lib_path2}) });
    exe.addObjectFile(.{ .cwd_relative = b.fmt("{s}/crti.o", .{lib_path1}) });
    exe.addObjectFile(.{ .cwd_relative = b.fmt("{s}/crtbegin.o", .{lib_path1}) });
    exe.addObjectFile(.{ .cwd_relative = b.fmt("{s}/crtend.o", .{lib_path1}) });
    exe.addObjectFile(.{ .cwd_relative = b.fmt("{s}/crtn.o", .{lib_path1}) });
}

fn getDepPath(b: *std.Build, name: []const u8) []const u8 {
    return if (b.option([]const u8, name, b.fmt("Path to {s} dependency", .{name}))) |path|
        b.findProgram(&.{name}, &.{path}) catch {
            std.log.err("Can't find {s} at provided path: {s}\n", .{ name, path });
            unreachable;
        }
    else
        b.findProgram(&.{name}, &.{}) catch {
            std.log.err("Can't find {s} in PATH\n", .{name});
            unreachable;
        };
}

fn parseCommand(b: *std.Build, argv: []const []const u8) []const u8 {
    return std.mem.trim(u8, b.run(argv), "\r\n");
}
