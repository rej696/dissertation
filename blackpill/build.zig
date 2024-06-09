const std = @import("std");

const exe_name = "firmware";

const c_src: []const []const u8 = &.{
    "hal/startup.c",
    // "main.c",
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
        .target = target,
        .optimize = optimize,
        .link_libc = false,
        .single_threaded = false,
        .root_source_file = b.path("src/main.zig"),
    });
    zig_obj.addIncludePath(b.path("inc"));

    const exe = b.addExecutable(.{
        .name = exe_name ++ ".elf",
        .target = target,
        .optimize = optimize,
        .link_libc = false,
        .linkage = .static,
        .single_threaded = true,
        // .root_source_file = b.path("src/main.zig"),
    });

    exe.addObject(zig_obj);

    setupArmGcc(b, exe);

    // setup linker script
    exe.entry = .{ .symbol_name = "_reset" };
    exe.link_gc_sections = true;
    exe.link_data_sections = true;
    exe.link_function_sections = true;
    exe.verbose_link = true;
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
            std.Target.arm.Feature.fp_armv8d16sp,
        },
    ),
};

/// ObjCopy an elf to a hex or bin format
fn extractBin(b: *std.Build, exe: *std.Build.Step.Compile, comptime format: std.Build.Step.ObjCopy.RawFormat) void {
    // const strip: std.Build.Step.ObjCopy.Strip = if (format == .bin) .debug_and_symbols else .none;
    const bin = b.addObjCopy(exe.getEmittedBin(), .{
        .format = format,
        // .only_sections = &.{
        //     ".vectors",
        //     ".text",
        //     ".rodata",
        //     ".data",
        //     ".bss",
        // },
    });
    bin.step.dependOn(&exe.step);
    const copy_bin = b.addInstallBinFile(bin.getOutput(), exe_name ++ "." ++ @tagName(format));
    b.default_step.dependOn(&copy_bin.step);
}

/// Find arm-none-eabi-gcc and associated built in libraries and link them into the exe
/// https://github.com/haydenridd/stm32-zig-porting-guide
fn setupArmGcc(b: *std.Build, exe: *std.Build.Step.Compile) void {
    // get the arm gcc compiler
    const arm_gcc_pgm = if (b.option([]const u8, "armgcc", "Path to arm-none-eabi-gcc compiler")) |arm_gcc_path|
        b.findProgram(&.{"arm-none-eabi-gcc"}, &.{arm_gcc_path}) catch {
            std.log.err("Can't find arm-none-eabi-gcc at provided path: {s}\n", .{arm_gcc_path});
            unreachable;
        }
    else
        b.findProgram(&.{"arm-none-eabi-gcc"}, &.{}) catch {
            std.log.err("Can't find arm-none-eabi-gcc in PATH\n", .{});
            unreachable;
        };

    // figure out paths to arm gcc built-in libraries
    const gcc_arm_sysroot_path = std.mem.trim(u8, b.run(&.{ arm_gcc_pgm, "-print-sysroot" }), "\r\n");
    const gcc_arm_multidir_relative_path = std.mem.trim(u8, b.run(&.{ arm_gcc_pgm, "-mcpu=cortex-m4", "-mfpu=fpv4-sp-d16", "-mfloat-abi=hard", "-print-multi-directory" }), "\r\n");
    const gcc_arm_version = std.mem.trim(u8, b.run(&.{ arm_gcc_pgm, "-dumpversion" }), "\r\n");
    const gcc_arm_lib_path1 = b.fmt("{s}/../lib/gcc/arm-none-eabi/{s}/{s}", .{ gcc_arm_sysroot_path, gcc_arm_version, gcc_arm_multidir_relative_path });
    const gcc_arm_lib_path2 = b.fmt("{s}/lib/{s}", .{ gcc_arm_sysroot_path, gcc_arm_multidir_relative_path });

    // manually add nano version of newlib c (--specs nano.specs -lc -lgcc)
    exe.addLibraryPath(.{ .path = gcc_arm_lib_path1 });
    exe.addLibraryPath(.{ .path = gcc_arm_lib_path2 });
    exe.addSystemIncludePath(.{ .path = b.fmt("{s}/include", .{gcc_arm_sysroot_path}) });
    exe.linkSystemLibrary("c_nano");

    // manually add c runtime objects bundled with arm-gcc
    exe.addObjectFile(.{ .path = b.fmt("{s}/crt0.o", .{gcc_arm_lib_path2}) });
    exe.addObjectFile(.{ .path = b.fmt("{s}/crti.o", .{gcc_arm_lib_path1}) });
    exe.addObjectFile(.{ .path = b.fmt("{s}/crtbegin.o", .{gcc_arm_lib_path1}) });
    exe.addObjectFile(.{ .path = b.fmt("{s}/crtend.o", .{gcc_arm_lib_path1}) });
    exe.addObjectFile(.{ .path = b.fmt("{s}/crtn.o", .{gcc_arm_lib_path1}) });
}
