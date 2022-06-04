const std = @import("std");

const mem = std.mem;
const debug = std.debug;
const unicode = std.unicode;

const psapi = windows.psapi;
const windows = std.os.windows;

pub const ProcessId = windows.DWORD;

pub const TCHAR = u8;

pub const BOOL = windows.BOOL;
pub const DWORD = windows.DWORD;
pub const HANDLE = windows.HANDLE;

pub const TRUE = windows.TRUE;
pub const CREATE_UNICODE_ENVIRONMENT = windows.CREATE_UNICODE_ENVIRONMENT;

pub const STARTUPINFOW = windows.STARTUPINFOW;
pub const STARTF_USESTDHANDLES = windows.STARTF_USESTDHANDLES;
pub const PROCESS_INFORMATION = windows.PROCESS_INFORMATION;
pub const SECURITY_ATTRIBUTES = windows.SECURITY_ATTRIBUTES;
pub const CreatePipe = windows.CreatePipe;
pub const SetHandleInformation = windows.SetHandleInformation;
pub const HANDLE_FLAG_INHERIT = windows.HANDLE_FLAG_INHERIT;
pub const LPSECURITY_ATTRIBUTES = [*c]windows.SECURITY_ATTRIBUTES;

  // 976:     try windows.CreatePipe(&rd_h, &wr_h, sattr);
  // 977      errdefer windowsDestroyPipe(rd_h, wr_h);

pub const CloseHandle = windows.CloseHandle;
pub const GetStdHandle = windows.GetStdHandle;
pub const CreateProcessW = windows.CreateProcessW;

pub const TerminateProcess = windows.TerminateProcess;
pub const WaitForSingleObjectEx = windows.WaitForSingleObjectEx;

pub const INFINITE = windows.INFINITE;


pub const STD_INPUT_HANDLE = windows.STD_INPUT_HANDLE;
pub const STD_ERROR_HANDLE = windows.STD_ERROR_HANDLE;
pub const STD_OUTPUT_HANDLE = windows.STD_OUTPUT_HANDLE;

pub const GetFileAttributes = windows.GetFileAttributes;
pub const ERROR_FILE_NOT_FOUND = c_long(2);
pub const INVALID_FILE_ATTRIBUTES = c_long(2);

pub const LPDWORD = [*c]DWORD;

pub const CREATE_SUSPENDED = 4;

pub const LIST_MODULES_64BIT = 0x02;
pub const LIST_MODULES_DEFAULT = 0x0;
pub const LIST_MODULES_ALL = LIST_MODULES_32BIT | LIST_MODULES_64BIT;
pub const LIST_MODULES_32BIT = 0x01;

pub const PTHREAD_START_ROUTINE = ?fn (LPVOID) callconv(.C) DWORD;
pub const LPTHREAD_START_ROUTINE = PTHREAD_START_ROUTINE;
// pub const struct__SECURITY_ATTRIBUTES = extern struct {
//     nLength: DWORD,
//     lpSecurityDescriptor: LPVOID,
//     bInheritHandle: BOOL,
// };
// pub const SECURITY_ATTRIBUTES = struct__SECURITY_ATTRIBUTES;
// pub const PSECURITY_ATTRIBUTES = [*c]struct__SECURITY_ATTRIBUTES;

// pub const LPSECURITY_ATTRIBUTES = [*c]struct__SECURITY_ATTRIBUTES;

pub extern "kernel32" fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) callconv(.Stdcall) HANDLE;

pub fn enumerateProcesses(processes: []ProcessId) ![]ProcessId {
    var needed_bytes: c_uint = undefined;
    const processes_size = @sizeOf(ProcessId) * @intCast(c_ulong, processes.len);
    const enum_result = psapi.EnumProcesses(processes.ptr, processes_size, &needed_bytes);
    if (enum_result == 0) return error.UnableToEnumerateProcesses;

    const number_of_processes = needed_bytes / @sizeOf(ProcessId);

    return processes[0..number_of_processes];
}

pub const LPCVOID = ?*anyopaque;
pub const LPVOID = *anyopaque;
const SIZE_T = windows.SIZE_T;

pub extern "kernel32" fn ReadProcessMemory(hProcess: HANDLE, lpBaseAddress: LPCVOID, lpBuffer: LPVOID, nSize: SIZE_T, lpNumberOfBytesRead: [*c]SIZE_T) callconv(.Stdcall) BOOL;


const AttachedWindowsProcess = struct {
    allocator: mem.Allocator,
    pid: u32,
    handle: HANDLE,
    base_dll_addr: u32,

    pub fn deinit(self: AttachedWindowsProcess) void {
        windows.CloseHandle(self.handle);
    }

    pub fn init(allocator: mem.Allocator, proc_name: []const u8) !AttachedWindowsProcess {
        // first, get all process id's
        var handles = try allocator.alloc(u32, 2048);
        defer allocator.free(handles);
        
        const procs = b: {
            var read_amount: u32 = 0;
            var winres = psapi.EnumProcesses(@ptrCast([*]u32, handles[0..]), handles.len * @sizeOf(u32), &read_amount);
            if(winres == 0) return error.Failure_PSAPI_EnumProcesses;

            // make sure that we have all process handles
            while(read_amount == handles.len) {
                // resize buffer
                var newbuf = try allocator.alloc(u32, handles.len * 2);
                allocator.free(handles);
                handles = newbuf;

                winres = psapi.EnumProcesses(@ptrCast([*]u32, handles[0..]), handles.len * @sizeOf(u32), &read_amount);
                if(winres == 0) return error.Failure_PSAPI_EnumProcesses;            
            }

            break :b handles[0..read_amount / @sizeOf(u32)];
        };

        std.log.debug("procs: {d}", .{procs.len});

        // try and identify which handle is the one we want
        const obj = b: {
            for(procs) |pid| {
                const chandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, windows.FALSE, pid);
                errdefer windows.CloseHandle(chandle);

                // ignore failed opens
                if(@ptrToInt(chandle) == 0) continue;

                var module = [_]windows.HMODULE{undefined};

                var bytes_needed: windows.DWORD = undefined;
                const winres = psapi.EnumProcessModulesEx(
                    chandle,
                    module[0..],
                    @sizeOf(u32),
                    &bytes_needed,
                    LIST_MODULES_ALL,
                );
                if(winres == 0) continue;

                var base_module_name: [windows.MAX_PATH:0]TCHAR = undefined;
                base_module_name[base_module_name.len - 1] = 0;

                const length_copied = psapi.GetModuleBaseNameA(
                    chandle,
                    module[0],
                    base_module_name[0..],
                    @sizeOf(@TypeOf(base_module_name)) / @sizeOf(TCHAR),
                );

                if(mem.eql(u8, proc_name, base_module_name[0..length_copied])) {
                    break :b AttachedWindowsProcess{
                        .allocator = allocator,
                        .pid = pid,
                        .base_dll_addr = @ptrToInt(module[0]),
                        .handle = chandle,
                    };
                }
                windows.CloseHandle(chandle);
            }
   
            return error.Failure_FailedToFindNamedWindowsProcess;
        };

        return obj;
    }

    pub fn readBytes(self: *AttachedWindowsProcess, addr: u32, comptime num_bytes: u32) ![num_bytes]u8 {
        var buf: [num_bytes]u8 = undefined;

        var bytes_read: u32 = 0;
        const winres = ReadProcessMemory(self.handle, @intToPtr(LPCVOID, addr), @ptrCast(LPVOID, &buf), buf.len, &bytes_read);
        if(winres == 0) return error.FailedToReadProcessMemory;
        return buf;
    }

    pub fn readStruct(self: *AttachedWindowsProcess, addr: u32, comptime T: type) !T {
        // Only extern and packed structs have defined in-memory layout.
        comptime debug.assert(@typeInfo(T).Struct.layout != std.builtin.TypeInfo.ContainerLayout.Auto);
        var res = try self.readBytes(addr, @sizeOf(T));
        return @bitCast(T, res);
    }

    pub fn readIntLittle(self: *AttachedWindowsProcess, addr: u32, comptime T: type) !T {
        const bytes = try self.readBytes(addr, (@typeInfo(T).Int.bits + 7) / 8);
        return mem.readIntLittle(T, &bytes);
    }
};

pub const LPCSTR = [*c]const windows.CHAR;
pub const LPSTR = [*:0]windows.CHAR;

pub extern "kernel32" fn GetFullPathNameA(lpFileName: LPCSTR, nBufferLength: DWORD, lpBuffer: LPSTR, lpFilePart: [*c]LPSTR) callconv(.Stdcall) DWORD;

pub const PROCESS_CREATE_THREAD = 2;
pub const PROCESS_QUERY_INFORMATION = 1024;
pub const PROCESS_VM_READ = 16;
pub const PROCESS_VM_WRITE = 32;
pub const PROCESS_VM_OPERATION = 8;

pub extern "kernel32" fn GetModuleHandleA(lpModuleName: LPCSTR) callconv(.Stdcall) windows.HMODULE;

pub const INT_PTR = c_longlong;
pub const FARPROC = ?fn (...) callconv(.C) INT_PTR;
pub const PAGE_READWRITE = 4;

pub extern "kernel32" fn GetProcAddress(hModule: windows.HMODULE, lpProcName: LPCSTR) callconv(.Stdcall) FARPROC;
pub extern "kernel32" fn VirtualAllocEx(hProcess: HANDLE, lpAddress: ?LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD) callconv(.Stdcall) LPVOID;

pub const AllocationType = packed struct {
    __padding1__: u12 = 0,
    commit: bool = false,
    reserve: bool = false,
    __padding2__: u5 = 0,
    reset: bool = false,
    // This should actually be there according to MSDN:
    // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
    // but doesn't seem to exist in my headers
    // reset_undo: bool = false,
    top_down: bool = false,
    __padding3__: u1 = 0,
    physical: bool = false,
    __padding5__: u6 = 0,
    large_pages: bool = false,
    __padding6__: u2 = 0,

    pub fn toDWORD(self: AllocationType) DWORD {
        const bytes = mem.toBytes(self);

        return mem.bytesToValue(DWORD, &bytes);
    }
};

pub fn writeProcessMemory(
    process_handle: HANDLE,
    starting_address: ?*c_ulong,
    buffer: []u8,
) !usize {
    var bytes_written: usize = undefined;
    return if (WriteProcessMemory(
        process_handle,
        @ptrCast(*c_ulong, starting_address),
        buffer.ptr,
        buffer.len,
        &bytes_written,
    ) != 0) bytes_written else error.UnableToWriteProcessMemory;
}

pub fn createRemoteThread(
    process_handle: HANDLE,
    thread_attributes: LPSECURITY_ATTRIBUTES,
    stack_size: usize,
    start_address: LPTHREAD_START_ROUTINE,
    parameter: LPVOID,
    flags: DWORD,
    thread_id: LPDWORD,
) !HANDLE {
    return CreateRemoteThreadEx(
        process_handle,
        thread_attributes,
        stack_size,
        start_address,
        parameter,
        flags,
        null,
        thread_id,
    );
}

pub const struct__PROC_THREAD_ATTRIBUTE_LIST = *anyopaque;
pub const PPROC_THREAD_ATTRIBUTE_LIST = ?*struct__PROC_THREAD_ATTRIBUTE_LIST;
pub const LPPROC_THREAD_ATTRIBUTE_LIST = ?*struct__PROC_THREAD_ATTRIBUTE_LIST;

pub extern "kernel32" fn WriteProcessMemory(hProcess: HANDLE, lpBaseAddress: ?LPVOID, lpBuffer: LPCVOID, nSize: SIZE_T, lpNumberOfBytesWritten: [*c]SIZE_T) callconv(.Stdcall) BOOL;
pub extern "kernel32" fn CreateRemoteThreadEx(hProcess: HANDLE, lpThreadAttributes: LPSECURITY_ATTRIBUTES, dwStackSize: SIZE_T, lpStartAddress: LPTHREAD_START_ROUTINE, lpParameter: LPVOID, dwCreationFlags: DWORD, lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST, lpThreadId: LPDWORD) callconv(.Stdcall) HANDLE;

pub fn injectDll(inject_handle: HANDLE, dll_name: []const u8) !DWORD {
    var zeroed_dll_name: [windows.MAX_PATH:0]u8 = undefined;
    mem.copy(u8, zeroed_dll_name[0..dll_name.len], dll_name);
    zeroed_dll_name[dll_name.len] = 0;

    var full_dll_path: [windows.MAX_PATH:0]u8 = undefined;

    const full_length = GetFullPathNameA(
        &zeroed_dll_name[0],
        windows.MAX_PATH,
        &full_dll_path,
        null,
    );  
    std.log.info("inject-dll-path='{s}'", .{zeroed_dll_name[0..dll_name.len]});

    const kernel32_module = b: {
        const m = GetModuleHandleA("kernel32.dll");
        if(@ptrToInt(inject_handle) == 0) return error.FailedToGetHandle;
        break :b m;
    };

    const load_library_ptr = GetProcAddress(kernel32_module, "LoadLibraryA") orelse return error.Failed_GetProcAddress;
    std.log.info("{any}", .{load_library_ptr});

    const memory = VirtualAllocEx(inject_handle, null, full_length + 1,
        (AllocationType{ .reserve = true, .commit = true }).toDWORD(),
        PAGE_READWRITE,
    );

    _ = try writeProcessMemory(
        inject_handle,
        @ptrCast(*c_ulong, @alignCast(@alignOf(*c_ulong), memory)),
        full_dll_path[0..(full_length + 1)],
    );

    const thread_handle = try createRemoteThread(
        inject_handle,
        null,
        0,
        @ptrCast(LPTHREAD_START_ROUTINE, load_library_ptr),
        memory,
        0,
        null,
    );

    _ = WaitForSingleObject(thread_handle, windows.INFINITE) catch {};
    const exit_code = getExitCodeThread(thread_handle) catch @panic("huh");
    _ = exit_code;

    return 0;
}

pub const PIPE_ACCESS_INBOUND = 0x00000001;
pub const PIPE_ACCESS_OUTBOUND = 0x00000002;
pub const PIPE_ACCESS_DUPLEX = 0x00000003;

pub const PIPE_TYPE_MESSAGE = 4;
pub extern "kernel32" fn CreateNamedPipeA(lpName: LPCSTR, dwOpenMode: DWORD, dwPipeMode: DWORD, nMaxInstances: DWORD, nOutBufferSize: DWORD, nInBufferSize: DWORD, nDefaultTimeOut: DWORD, lpSecurityAttributes: LPSECURITY_ATTRIBUTES) callconv(.Stdcall) HANDLE;
pub extern "kernel32" fn DisconnectNamedPipe(hNamedPipe: HANDLE)  callconv(.Stdcall) BOOL;

pub const ReadFile = windows.ReadFile;
pub extern "kernel32" fn ConnectNamedPipe(hNamedPipe: HANDLE, lpOverlapped: LPOVERLAPPED) callconv(.Stdcall) BOOL;

pub fn getExitCodeThread(handle: HANDLE) !DWORD {
    var exit_code: DWORD = undefined;
    if (GetExitCodeThread(handle, &exit_code) == 0) {
        return error.UnableToGetExitCodeFromThread;
    }

    return exit_code;
}

pub const WaitForSingleObject = windows.WaitForSingleObject;
// pub extern "kernel32" fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) callconv(.Stdcall) DWORD;
pub extern "kernel32" fn GetExitCodeThread(hThread: HANDLE, lpExitCode: LPDWORD) callconv(.Stdcall) BOOL;

pub const struct__OVERLAPPED = extern struct {
    Internal: ULONG_PTR,
    InternalHigh: ULONG_PTR,
    @"": extern union {
        @"": extern struct {
            Offset: DWORD,
            OffsetHigh: DWORD,
        },
        Pointer: PVOID,
    },
    hEvent: HANDLE,
};
pub const OVERLAPPED = struct__OVERLAPPED;
pub const LPOVERLAPPED = [*c]struct__OVERLAPPED;
pub const ULONG_PTR = c_ulonglong;
pub const PVOID = ?*anyopaque;
pub extern "kernel32" fn GetLastError() callconv(.Stdcall) DWORD;

const LogPipe = struct {
    fn start(server_pipe: HANDLE) void {

        const is_pipe_connected = ConnectNamedPipe(server_pipe, null);
        if(is_pipe_connected == 0) {
            std.log.err("log-pipe connection failure", .{});
            std.log.info("{d}", .{GetLastError()});
            @panic("");
        }

        std.log.info("pipe connected\n", .{});
        while(true) {
            var msg: [1024]u8 = undefined;
            var bytes_read: u32 = 0;
            var winret = ReadFile(server_pipe, &msg, msg.len, &bytes_read, null);
            while(winret == 0) {
                winret = ReadFile(server_pipe, &msg, msg.len, &bytes_read, null);
                std.log.info("{d}", .{GetLastError()});
                // @panic("log-pipe-read failure");
            }

            // if(bytes_read != 0) {
            std.log.info("dll: {s}", .{msg[0..bytes_read]});    
            // }
        }
    }
};


pub extern "kernel32" fn ResumeThread(hThread: HANDLE) callconv(.Stdcall) DWORD;
pub const ERROR_IO_PENDING = @as(c_long, 997);