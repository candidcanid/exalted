const std = @import("std");

const debug = std.debug;
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const heap = std.heap;
const os = std.os;

const windows = os.windows;
const user32 = windows.user32;
const psapi = std.os.windows.psapi;

pub const DLL_PROCESS_ATTACH = 1;
pub const DLL_PROCESS_DETACH = 0;
pub const DLL_THREAD_ATTACH = 2;
pub const DLL_THREAD_DETACH = 3;

const mutonEntry = @import("./thread_main.zig").mutonEntry;

var muton_thread: ?std.Thread = null;

pub export fn DllMain(_: windows.HANDLE, reason: windows.DWORD, _: windows.LPVOID) callconv(.Stdcall) windows.BOOL {
    switch (reason) {
        DLL_PROCESS_ATTACH => {
            if(muton_thread == null) muton_thread = std.Thread.spawn(.{}, mutonEntry, .{}) catch @panic("could not create injector thread");
        },
        else => {},
    }

    return windows.TRUE;
}
