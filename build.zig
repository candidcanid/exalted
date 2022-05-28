const std = @import("std");

const log = std.log;

pub fn build(b: *std.build.Builder) !void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const default_xcom_path = "C:\\XCOM Enemy Unknown\\XEW\\Binaries\\Win32\\";
    const XComEW_path = b.option([]const u8, 
        "XComEWDirectory", comptime std.fmt.comptimePrint("directory that 'XComEW.exe' resides in (e.g. '{s}')", .{default_xcom_path}),
    ) orelse default_xcom_path;
        
    const exalted_options = b: {
        // exalted (injector) build options
        const e_dryrun = b.option(bool, "e_dryrun", "only check that exalted runs on remote system, becomes a no-op program") orelse false;
        const e_script = b.option([]const u8, "e_script", "embed a frida .js script, to run after dll-injection") orelse null;
        const no_inject = b.option(bool, "no_inject", "embed a frida .js script, to run after dll-injection") orelse false;

        const build_options = b.addOptions();
        build_options.addOption(bool, "no_inject", no_inject);
        build_options.addOption(bool, "e_dryrun", e_dryrun);
        build_options.addOption(?[]const u8, "e_script", e_script);
        build_options.addOption([]const u8, "XComEW_path", XComEW_path);
        break :b build_options;
    };

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

    const exe = b.addExecutable("exalted", "src/main.zig");
    {
        
        exe.step.dependOn(&muton_dll.install_step.?.step);

        exe.addOptions("exalted_options", exalted_options);
        
        exe.linkSystemLibrary("c");

        exe.linkSystemLibrary("gdi32");
        exe.linkSystemLibrary("user32");
        exe.linkSystemLibrary("kernel32");
        
        exe.setTarget(target);
        exe.setBuildMode(mode);
        exe.install();
    }

    // 'local' run, use if building on non-vm machine
    const run_step = b.step("run", "Run the app");
    {
        // const exalted_path = try std.fmt.allocPrint(b.allocator, "{s}\\bin\\exalted.exe", .{b.install_path});
        // const local_exec = b.addSystemCommand(&[_][]const u8{
        //     exalted_path, 
        // });

        // // TODO: can we check to see if target != i386-windows, and have it error out accordingly?
        const run_cmd = exe.run();
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }
        run_step.dependOn(&run_cmd.step);
    }

    // 'vm' run, connects to parallels windows VM and runs program
    //   requires that VM can access directory (and all sub-directorys) this build.zig resides in
    const vmrun_step = b.step("vmrun", "Run exalted remotely by connecting to a Parallels Windows VM");
    {
        vmrun_step.dependOn(b.getInstallStep());
        const vm_target = b.option([]const u8, "vm", "name of Parallels Windows VM to connect to (default is 'Windows 11')") orelse "Windows 11";
        
        // const vm_UUID = b: {
        //     var child = std.ChildProcess.init(&.{
        //         "prlctl", "list", "name", vm_target, "--no-header", "-o", "uuid"
        //     }, b.allocator);
            
        //     child.stdin_behavior = .Ignore;
        //     child.stdout_behavior = .Pipe;
            
        //     child.spawn() catch |err| {
        //         log.warn("Unable to spawn {s}: {s}\n", .{ "prlctl", @errorName(err) });
        //         return err;
        //     };
            
        //     const stdout = child.stdout.?.reader().readAllAlloc(b.allocator, 600) catch {
        //         return error.ReadFailure;
        //     };
        //     errdefer b.allocator.free(stdout);

        //     const term = try child.wait();
        //     switch (term) {
        //         .Exited => |code| {
        //             if (code != 0) {
        //                 _ = @truncate(u8, code);
        //                 return error.ExitCodeFailure;
        //             }
        //             const uuid = std.mem.trimRight(u8, stdout, &.{'\n'});
        //             // strip '{', '}'
        //             break :b uuid[1..uuid.len-1];
        //         },
        //         .Signal, .Stopped, .Unknown => |code| {
        //             _ = @truncate(u8, code);
        //             return error.ProcessTerminated;
        //         },
        //     }
        // };

        // log.info("Parallels VM \"{s}\" has UUID \"{s}\"", .{vm_target, vm_UUID});
        // FIXME: maybe better way to get this path?
        const exalted_path = try std.fmt.allocPrint(b.allocator, "{s}/bin/exalted.exe", .{b.install_path});
        const vm_exec = b.addSystemCommand(&[_][]const u8{
            "prlctl", "exec", vm_target, "--current-user", "-r", "powershell", exalted_path, 
        });
        vm_exec.cwd = try std.fmt.allocPrint(b.allocator, "{s}/bin/", .{b.install_path});

        vmrun_step.dependOn(&vm_exec.step);
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
