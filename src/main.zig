const std = @import("std");

const fs = std.fs;
const io = std.io;
const mem = std.mem;
const log = std.log;
const unicode = std.unicode;
const assert = std.debug.assert;

const winapi = @import("winapi.zig");
const exalted_options = @import("exalted_options");

pub const TmpDir = struct {
    dir: std.fs.Dir,
    parent_dir: std.fs.Dir,
    sub_path: [sub_path_len]u8,

    const random_bytes_count = 12;
    const sub_path_len = std.fs.base64_encoder.calcSize(random_bytes_count);

    pub fn cleanup(self: *TmpDir) void {
        self.dir.close();
        self.parent_dir.deleteTree(&self.sub_path) catch {};
        self.parent_dir.close();
        self.* = undefined;
    }
};

pub fn tmpDir(opts: std.fs.Dir.OpenDirOptions) !TmpDir {
    var allocator = std.heap.c_allocator;

    var random_bytes: [TmpDir.random_bytes_count]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    var sub_path: [TmpDir.sub_path_len]u8 = undefined;
    _ = std.fs.base64_encoder.encode(&sub_path, &random_bytes);

    const tmpdata_path = try fs.getAppDataDir(allocator, "Temp");
    defer allocator.free(tmpdata_path);
    log.debug("tmpdata_path: {s}", .{tmpdata_path});

    var parent_dir = std.fs.cwd().makeOpenPath(tmpdata_path, .{}) catch
        @panic("unable to make tmp dir: unable to make and open 'C:\\Users\\AppData\\Local\\Temp' dir");
    var dir = parent_dir.makeOpenPath(&sub_path, opts) catch
        @panic("unable to make tmp dir: unable to make and open the tmp dir");

    return TmpDir{
        .dir = dir,
        .parent_dir = parent_dir,
        .sub_path = sub_path,
    };
}

const PipeThread = struct {
    fn loop(read_h: winapi.HANDLE) !void {
        var pipebuf: [2046]u8 = undefined;
        while(true) {
            const bytes_read = try winapi.ReadFile(read_h, pipebuf[0..], null, .blocking);
            _ = std.io.getStdOut().writer().write(pipebuf[0..bytes_read]) catch unreachable;    
        }
    }
};

fn attachFridaScript(frida_script_path: []const u8, pipe_write_h: winapi.HANDLE) !winapi.HANDLE {
    var allocator = std.heap.c_allocator;

    const appdata_path = try fs.getAppDataDir(allocator, "");
    defer allocator.free(appdata_path);

    const pypath = try std.fs.path.join(allocator, &.{
        appdata_path, "\\Programs\\Python\\Python310\\python.exe",
    });
    defer allocator.free(pypath);
    std.log.debug("pypath: {s}", .{pypath});
    
    const pycwd = try std.fs.path.join(allocator, &.{
        appdata_path, "\\Temp\\",
    });
    defer allocator.free(pycwd);
    std.log.debug("pycwd: {s}", .{pycwd});

    const app_path_w = try unicode.utf8ToUtf16LeWithNull(allocator, pypath);
    defer allocator.free(app_path_w);
    
    const cmdline = try std.fmt.allocPrint(allocator, "-u {s}", .{frida_script_path});
    defer allocator.free(cmdline);

    const cmd_line_w = try unicode.utf8ToUtf16LeWithNull(allocator, cmdline);
    defer allocator.free(cmd_line_w);

    const cwd_w = try unicode.utf8ToUtf16LeWithNull(allocator, pycwd);
    defer allocator.free(cwd_w);

    var siStartInfo = winapi.STARTUPINFOW{
        .cb = @sizeOf(winapi.STARTUPINFOW),
        .hStdError = pipe_write_h,
        .hStdOutput = pipe_write_h,
        .hStdInput = try winapi.GetStdHandle(winapi.STD_INPUT_HANDLE),
        .dwFlags = winapi.STARTF_USESTDHANDLES,

        .lpReserved = null,
        .lpDesktop = null,
        .lpTitle = null,
        .dwX = 0,
        .dwY = 0,
        .dwXSize = 0,
        .dwYSize = 0,
        .dwXCountChars = 0,
        .dwYCountChars = 0,
        .dwFillAttribute = 0,
        .wShowWindow = 0,
        .cbReserved2 = 0,
        .lpReserved2 = null,
    };
    var piProcInfo: winapi.PROCESS_INFORMATION = undefined;

    try winapi.CreateProcessW(
        app_path_w,
        cmd_line_w,
        null,
        null,
        winapi.TRUE,
        winapi.CREATE_UNICODE_ENVIRONMENT,
        null,
        // @ptrCast(?*anyopaque, envp_ptr),
        cwd_w,
        &siStartInfo,
        &piProcInfo,
    );

    var proc_handle = piProcInfo.hProcess;
    return proc_handle;
}

pub fn main() anyerror!void {
    var allocator = std.heap.c_allocator;

    if(exalted_options.e_dryrun == true) {
        log.info("e_dryrun, ending without doing anything", .{});
        return;
    }

    if(exalted_options.e_script) |frida_script_path| {
        log.info("attaching frida script '{s}'", .{frida_script_path});
    }

    var tmp = try tmpDir(.{});
    defer tmp.cleanup();    

    const dll_path = b: {
        var file = try tmp.dir.createFile("injected.dll", .{.exclusive = true});
        errdefer file.close();

        var buf_stream = std.io.bufferedWriter(file.writer());
        const st = buf_stream.writer();
        _ = try st.write(@embedFile("../zig-out/bin/muton.dll"));
        try buf_stream.flush();
        file.close();

        break :b tmp.dir.realpathAlloc(allocator, "injected.dll") catch
            @panic("failed getting realpath for injected.dll");
    };
    defer allocator.free(dll_path);

    const frida_script_path: ?[]const u8 = if(exalted_options.e_script) |frida_jspath| convert: {
        const frida_js_script = @embedFile("../" ++ frida_jspath);

        const frida_script = b: {
            const b64e = std.base64.standard.Encoder;
            var outbuf = try allocator.alloc(u8, b64e.calcSize(frida_js_script.len));
            defer allocator.free(outbuf);

            const frida_source = b64e.encode(outbuf[0..], frida_js_script);
            break :b try std.fmt.allocPrint(allocator,
        \\import sys
        \\import base64
        \\import frida
        \\import time
        \\
        \\def main():
        \\    session = frida.attach("XComEW.exe")
        \\    script = b"{s}"
        \\    source = base64.b64decode(script).decode("utf-8")
        \\    script = session.create_script(source)
        \\    print(">> LOADING SCRIPT <<")
        \\    script.load()
        \\    while True:
        \\        time.sleep(1)
        \\    # sys.stdin.read()
        \\    # session.detach()
        \\    
        \\main()
            , .{frida_source});
        };
        defer allocator.free(frida_script);

        const frida_script_path = b: {
            var file = tmp.dir.createFile("trace.py", .{.exclusive = true}) catch
                @panic("failed creating file for trace.py");
            errdefer file.close();

            var buf_stream = std.io.bufferedWriter(file.writer());
            const st = buf_stream.writer();
            _ = try st.write(frida_script);
            try buf_stream.flush();
            file.close();

            break :b tmp.dir.realpathAlloc(allocator, "trace.py") catch
                @panic("failed getting realpath for trace.py");
        };
        std.log.debug("frida-wrapper-script: {s}", .{frida_script_path});
        break :convert frida_script_path;
    } else null;
    defer if(frida_script_path) |fp| allocator.free(fp);

    // TODO: verify that XComEW exists at the given path
    const XComEW_path = exalted_options.XComEW_path;
    const XComEW_exepath = exalted_options.XComEW_path ++ "\\XComEW.exe";

    const app_path_w = try unicode.utf8ToUtf16LeWithNull(allocator, XComEW_exepath);
    defer allocator.free(app_path_w);
    
    const cmd_line_w = try unicode.utf8ToUtf16LeWithNull(allocator, "");
    defer allocator.free(cmd_line_w);

    const cwd_w = try unicode.utf8ToUtf16LeWithNull(allocator, XComEW_path);
    defer allocator.free(cwd_w);

    // setup pipe wrapper for XComEW stdout/stderr
    var secAttr: winapi.SECURITY_ATTRIBUTES = .{
        .nLength = @sizeOf(winapi.SECURITY_ATTRIBUTES),
        .lpSecurityDescriptor = null,
        .bInheritHandle = winapi.TRUE,
    };

    var pipe_read_h: winapi.HANDLE = undefined;
    var pipe_write_h: winapi.HANDLE = undefined;
    try winapi.CreatePipe(&pipe_read_h, &pipe_write_h, &secAttr);
    try winapi.SetHandleInformation(pipe_read_h, winapi.HANDLE_FLAG_INHERIT, 0);

    var pipethread = try std.Thread.spawn(.{}, PipeThread.loop, .{pipe_read_h});
    _ = pipethread;

    var siStartInfo = winapi.STARTUPINFOW{
        .cb = @sizeOf(winapi.STARTUPINFOW),
        .hStdError = pipe_write_h,
        .hStdOutput = pipe_write_h,
        .hStdInput = try winapi.GetStdHandle(winapi.STD_INPUT_HANDLE),
        .dwFlags = winapi.STARTF_USESTDHANDLES,

        .lpReserved = null,
        .lpDesktop = null,
        .lpTitle = null,
        .dwX = 0,
        .dwY = 0,
        .dwXSize = 0,
        .dwYSize = 0,
        .dwXCountChars = 0,
        .dwYCountChars = 0,
        .dwFillAttribute = 0,
        .wShowWindow = 0,
        .cbReserved2 = 0,
        .lpReserved2 = null,
    };
    var piProcInfo: winapi.PROCESS_INFORMATION = undefined;

    // TODO: shift to some 'winapi' lib
    const CREATE_SUSPENDED = 4;

    try winapi.CreateProcessW(
        app_path_w,
        cmd_line_w,
        null,
        null,
        winapi.TRUE,
        winapi.CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
        null,
        // @ptrCast(?*anyopaque, envp_ptr),
        cwd_w,
        &siStartInfo,
        &piProcInfo,
    );

    errdefer {
        winapi.CloseHandle(piProcInfo.hThread);
        winapi.TerminateProcess(piProcInfo.hProcess, 0) catch {};
    }

    const frida_py_handle: ?winapi.HANDLE = if(frida_script_path) |fscript| b: {
        log.info("injecting frida script", .{});
        const frida_script_handle = try attachFridaScript(fscript, pipe_write_h);
        std.time.sleep(4 * std.time.ns_per_s);
        break :b frida_script_handle;
    } else null;
    defer if(frida_py_handle) |h| winapi.TerminateProcess(h, 0) catch {};

    log.info("XComEW.exe launched in suspended state", .{});
    if(exalted_options.no_inject == true) {
        log.info("no_inject=true, skipping injection", .{});
    } else {
        log.info("injecting .dll", .{});
        _ = try winapi.injectDll(piProcInfo.hProcess, dll_path);    
    }

    log.info("resuming XComEW.exe", .{});
    _ = winapi.ResumeThread(piProcInfo.hThread);

    try winapi.WaitForSingleObject(piProcInfo.hProcess, winapi.INFINITE);

    log.info("XComEW.exe exited", .{});
}

    