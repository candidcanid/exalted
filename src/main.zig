const std = @import("std");

const fs = std.fs;
const io = std.io;
const mem = std.mem;
const log = std.log;
const unicode = std.unicode;
const assert = std.debug.assert;

const clap = @import("zig-clap");
const winapi = @import("winapi.zig");

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

pub fn main() anyerror!void {
    var allocator = std.heap.c_allocator;

    const params = comptime clap.parseParamsComptime(
        \\-h, --help             Display this help and exit.
        \\--dryrun               exit right after argument parsing
        \\--exe <str>            path of .exe to launch, pause, inject .dll, continue
        \\--dll <str>            path of .dll to inject into launched .exe
        \\
    );

    // Initalize our diagnostics, which can be used for reporting useful errors.
    // This is optional. You can also pass `.{}` to `clap.parse` if you don't
    // care about the extra information `Diagnostics` provides.
    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, .{
        .diagnostic = &diag,
    }) catch |err| {
        // Report useful error and exit
        std.log.err("failed to parse arguments: {s}", .{@errorName(err)});
        return;
    };
    defer res.deinit();

    if(res.args.dryrun) {
        log.info("e_dryrun, ending without doing anything", .{});
        return;
    }

    const exe_path = res.args.exe orelse {
        std.log.err(".exe file for injection/attachment must be specified with --exe!", .{});
        return;
    };

    // check that exe file exists
    _ = std.os.access(exe_path, 0) catch |err| {
        std.log.err("invalid .exe path '{s}':{s}", .{exe_path, @errorName(err)});
        return;
    };

    const exe_dir = std.fs.path.dirname(exe_path) orelse unreachable;
    const exe_name = std.fs.path.basename(exe_path);
    
    // FIXME: this fails .. even though the dll path exists?
    // if(res.args.dll) |dll_path| {
    //     // _ = std.os.access(dll_path, 0) catch |err| {
    //     //     std.log.err("invalid .dll path '{s}':{s}", .{dll_path, @errorName(err)});
    //     //     return;
    //     // };
    // }

    var tmp = try tmpDir(.{});
    defer tmp.cleanup();    

    const app_path_w = try unicode.utf8ToUtf16LeWithNull(allocator, exe_path);
    defer allocator.free(app_path_w);
    
    const cmd_line_w = try unicode.utf8ToUtf16LeWithNull(allocator, "");
    defer allocator.free(cmd_line_w);

    const cwd_w = try unicode.utf8ToUtf16LeWithNull(allocator, exe_dir);
    defer allocator.free(cwd_w);

    // setup pipe wrapper for .exe stdout/stderr
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

    try winapi.CreateProcessW(
        app_path_w,
        cmd_line_w,
        null,
        null,
        winapi.TRUE,
        winapi.CREATE_UNICODE_ENVIRONMENT | winapi.CREATE_SUSPENDED,
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

    log.info("{s} launched in suspended state", .{exe_name});
    if(res.args.dll) |dll_path| {
        _ = try winapi.injectDll(piProcInfo.hProcess, dll_path);    
    } else log.info("no .dll specified, skipping injection", .{});

    log.info("resuming {s}", .{exe_name});
    _ = winapi.ResumeThread(piProcInfo.hThread);

    try winapi.WaitForSingleObject(piProcInfo.hProcess, winapi.INFINITE);
    log.info("{s} exited", .{exe_name});
}

    