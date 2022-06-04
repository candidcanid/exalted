const std = @import("std");
const builtin = @import("builtin");

const os = std.os;
const fs = std.fs;
const log = std.log;

pub fn build(b: *std.build.Builder) !void {
    if(builtin.os.tag != .windows and builtin.os.tag != .macos) {
        std.log.err("exalted only supports building on windows or macOS systems", .{});
        return;
    }

    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const default_XComEWexe_path = "C:\\XCOM Enemy Unknown\\XEW\\Binaries\\Win32\\XComEW.exe";
    const XComEWexe_path = b.option([]const u8, 
        "XComEWexe", comptime std.fmt.comptimePrint("path that 'XComEW.exe' resides in (e.g. '{s}')", .{default_XComEWexe_path}),
    ) orelse default_XComEWexe_path;

    const muton_options = b: {
        const dump_GNatives = b.option(bool, "dump_GNatives", "after injection, dump out GNative table and exit") orelse false;

        // muton (injected-dll) build options
        const build_options = b.addOptions();
        build_options.addOption(bool, "dump_GNatives", dump_GNatives);

        break :b build_options;
    };
    
    const muton_dll = b.addSharedLibrary(
        "muton",
        "src/muton/dll_main.zig",
        .{.versioned = .{ .major = 0, .minor = 1 }},
    );
    {
        muton_dll.addOptions("muton_options", muton_options);

        muton_dll.linkLibC();
        muton_dll.linkSystemLibrary("kernel32");
        {
            const dll_path = try std.fmt.allocPrint(b.allocator, "{s}/bin", .{b.install_path});
            // defer b.allocator.free(dll_path); TODO: does this break anything by freeing?
            muton_dll.setOutputDir(dll_path);
        }
        muton_dll.setTarget(target);
        muton_dll.setBuildMode(mode);
        muton_dll.install();
    }

    const zig_clap = std.build.Pkg{
        .name = "zig-clap",
        .path = .{ .path = "dependencies/zig-clap/clap.zig" },
        .dependencies = &[_]std.build.Pkg{},
    };

    const exe = b.addExecutable("exalted", "src/main.zig");
    {
        exe.addPackage(zig_clap);

        exe.step.dependOn(&muton_dll.install_step.?.step);

        exe.linkSystemLibrary("c");

        exe.linkSystemLibrary("gdi32");
        exe.linkSystemLibrary("user32");
        exe.linkSystemLibrary("kernel32");
        
        exe.setTarget(target);
        exe.setBuildMode(mode);
        exe.install();
    }

    if(comptime builtin.os.tag == .macos) {
        const vm_target = b.option([]const u8, "vm", "name of Parallels Windows VM to connect to (default is 'Windows 11')") orelse "Windows 11";
        const no_dll_inject = b.option(bool, "no_inject", "skip injecting muton.dll") orelse false;

        const home_dir = os.getenv("HOME") orelse {
            std.log.err("getenv(\"HOME\") must return something for macOS builds", .{});
            return;
        };

        std.log.info("{s}", .{@tagName(builtin.os.tag)});

        const remote_exalted_path = b: {
            const relpath = try fs.path.relative(b.allocator, home_dir, try std.fmt.allocPrint(b.allocator, "{s}/bin/exalted.exe", .{b.install_path}));
            const remote_path = try fs.path.join(b.allocator, &.{"//Mac/Home/", relpath});
            std.mem.replaceScalar(u8, remote_path, '/', '\\');
            break :b remote_path;
        };

        const remote_muton_path = b: {
            const relpath = try fs.path.relative(b.allocator, home_dir, try std.fmt.allocPrint(b.allocator, "{s}/bin/muton.dll", .{b.install_path}));
            const remote_path = try fs.path.join(b.allocator, &.{"//Mac/Home/", relpath});
            std.mem.replaceScalar(u8, remote_path, '/', '\\');
            break :b remote_path;
        };

        // 'vm' run, connects to parallels windows VM and runs program
        //   requires that VM can access directory (and all sub-directorys) this build.zig resides in
        const vmrun_step = b.step("vmrun", "Run exalted remotely by connecting to a Parallels Windows VM");
        {
            vmrun_step.dependOn(b.getInstallStep());
            
            var exalted_args = std.ArrayList([]const u8).init(b.allocator);
            try exalted_args.appendSlice(&.{"--exe", try std.fmt.allocPrint(b.allocator, "\\\"{s}\\\"", .{XComEWexe_path})});
            if(no_dll_inject == false) {
                try exalted_args.appendSlice(&.{"--dll", try std.fmt.allocPrint(b.allocator, "\\\"{s}\\\"", .{remote_muton_path})});
            }

            const vm_exec = b.addSystemCommand(&[_][]const u8{
                "prlctl", "exec", vm_target, "--current-user", "powershell", "-Command",
                b: {
                    const powershell_cmd = try std.fmt.allocPrint(b.allocator, "& {{Start-Process -NoNewWindow -Wait -FilePath '{s}' -ArgumentList '{s}' }}", .{
                        remote_exalted_path,
                        std.mem.join(b.allocator, " ", exalted_args.items),
                    });
                    std.log.info("cmd: {s}", .{powershell_cmd});
                    break :b powershell_cmd;
                },
            });

            vmrun_step.dependOn(&vm_exec.step);
        }
    } 

    if(comptime builtin.os.tag == .windows) {
        // 'local' run, use if building on non-vm machine
        const run_step = b.step("run", "Run the app");
        {
            const run_cmd = exe.run();
            run_cmd.step.dependOn(b.getInstallStep());
            if (b.args) |args| {
                run_cmd.addArgs(args);
            }
            run_step.dependOn(&run_cmd.step);
        }

        // perform various batch/sanity tests
        const test_step = b.step("test", "Run unit tests");
        {
            // TODO: currently no tests, should add some! :P
            //  maybe if running on non-windows .. see if wine is avaliable & use it for running tests?
            const exe_tests = b.addTest("src/main.zig");
            exe_tests.setTarget(target);
            exe_tests.setBuildMode(mode);

            test_step.dependOn(&exe_tests.step);
        }
    }
}
