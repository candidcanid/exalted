const std = @import("std");

const debug = std.debug;
const mem = std.mem;
const testing = std.testing;
const heap = std.heap;
const os = std.os;

const muton_options = @import("muton_options");
const XComEW = @import("./XComEW.zig");
const UE3 = XComEW.UE3;

fn log(comptime fmt: []const u8, args: anytype) void {
    std.debug.getStderrMutex().lock();
    defer std.debug.getStderrMutex().unlock();
    const stderr = std.io.getStdErr().writer();
    nosuspend stderr.print(fmt, args) catch return;
    nosuspend stderr.print("\n", .{}) catch return;
}

// walks through FNativeFunctionLookup to map function names to native functions
fn identifyNativeConstructs() void {
    const xcom_GNativeLookupFuncs = XComEW.FNativeFunctionLookup.ptr;
    log("GNativeLookupFuncs = {x}", .{@ptrToInt(xcom_GNativeLookupFuncs)});

    {
        var it = xcom_GNativeLookupFuncs.entryIterator();
        while(it.next()) |entry| {
            const fname = entry.pair.key;
            var lookup = entry.pair.value;
            log("# GNativeLookupFuncs - '{s}', table = {x}", .{fname.entry().utf8_string(), @ptrToInt(lookup.items)});
            {
                var lookup_it = lookup.iterator();
                while(lookup_it.next()) |item| {
                    log("    ('{s}', 0x{x}), ", .{item.cstr, @ptrToInt(item.fptr)});
                }
            }
        }
    }
}

fn dumpGNativeTable(allocator: mem.Allocator) !void {
    _ = allocator;
    // simple wait for everything to initialise
    std.time.sleep(7 * std.time.ns_per_s);

    var nfound: u32 = 0;
    for(XComEW.GObjectObjs.slice()) |uobj| {
        if(mem.eql(u8, "Function", uobj.class.namestr()[0.."Function".len])) {
            var ufunc = @ptrCast(*UE3.UFunction, uobj);
            if(ufunc.iNative != 0) {
                nfound += 1;
                log("(ntl = {d}) {s}::exec{s} = {x};", .{ufunc.iNative, uobj.outer.namestr(), uobj.namestr(), @ptrToInt(ufunc.Func)});
            }
        }
    }

    log("found {} GNative entries", .{nfound});

    // var entries = std.AutoHashMap([*:0]const u8, u32).init(allocator);

    // // 0x188fdc0 - 'default' vtable?
    // for(gobjs.slice()) |uobj| {
    //     if(uobj.vtable == 0x188fdc0) continue;

    //     if(entries.get(uobj.class.namestr())) |vtable| {
    //         _ = vtable;
    //         // if(vtable != uobj.vtable) log("???", .{});
    //     } else {
    //         log("  ('{s}', 0x{x}),", .{uobj.class.namestr(), uobj.vtable});
    //         entries.put(uobj.class.namestr(), uobj.vtable) catch unreachable;
    //     }
    // }

    // // for(gobjs.slice()) |uobj, idx| {
    //     if(mem.eql(u8, "Function", uobj.class.namestr()[0.."Function".len])) {
    //         // if(mem.eql(u8, "IsGravelyInjured", uobj.namestr()[0.."IsGravelyInjured".len])) {
    //             var ufunc = @ptrCast(*UFunction, uobj);
    //             if(ufunc.iNative != 0) {
    //                 log("(ntl = {d}) {s}::exec{s} = {x};", .{ufunc.iNative, uobj.outer.namestr(), uobj.namestr(), @ptrToInt(ufunc.Func)});            

    //                 // UObject::ProcessInternal
    //             // if(@ptrToInt(ufunc.Func) != 0x4a3b50 and @ptrToInt(ufunc.Func) != 0x0) {
    //                 // log("UObject::GObjObjects[{d}] = {s}:{s} = {x};", .{idx, uobj.namestr(), uobj.class.namestr(), @ptrToInt(ufunc.Func)});            
    //             }
                
    //             // var ufunc = @ptrCast([*]align (1) u32, uobj);
    //             // for(ufunc[0..0x300 / 0x4]) |val, off| {
    //             //     log("{x}: {x}", .{off * 0x4, val});
    //             // }
    //         // }
    //     }
    //     // if(uobj.class == null) log("UObject::GObjObjects[{d}] = {s}:NULLCLASS", .{idx, uobj.namestr()});
}

pub fn mutonEntry() void {
    mutonMain() catch |err| {
        if(err == error.TerminateXComProcess) {
            log("terminating XComEW.exe early", .{});
            std.os.exit(0);
        // TODO: list out the exception
        } else @panic("mutonMain had exception!");
    };
}

pub fn mutonMain() !void {
    log("mutonMain - entry", .{});
    var allocator = std.heap.c_allocator;

    if(muton_options.dump_GNatives == true) {
        log("dumping GNatives", .{});
        try dumpGNativeTable(allocator);
        // not interested in running after dump
        return error.TerminateXComProcess;
    }

    // log("::info::", .{});

    // identifyNativeConstructs();
    // identifyUObjectVtables();

    // FNativeFunctionLookup
    // const char *Name
    // void (__cdecl *Pointer)(UObject *this, FFrame *, void *const)

    // log("GNativeLookupFuncs.Elements.Data = {x}", .{@ptrToInt(xcom_GNativeLookupFuncs.Elements.data)});

    // for(xcom_GNativeLookupFuncs.Elements.data[0..20]) |entry, table_idx| {
    //     if(entry.data0x8) |table| {
    //         log("table: {x}", .{@ptrToInt(table)});
    //         var idx: u32 = 0;
    //         while(table[idx].key != 0x0) : (idx += 1) {
    //             log("hashslot[{d}].items[{d}]: {{key = '{s}', val = (fptr*) {x}}}", .{table_idx, idx, @intToPtr([*:0]u8, table[idx].key), table[idx].val});
    //         }
    //     }
    // }

    // log("FName.Names = 0x{x}, length={d}, capacity={d}", .{XComStructOffset_Names, names.length, names.capacity});
    // log("UObject::GObjObjects = data=0x{x}, length={d}, capacity={d}", .{@ptrToInt(gobjs.data), gobjs.length, gobjs.capacity});
    
    // for(gobjs.slice()) |uobj| {
    // // for(gobjs.slice()) |uobj, idx| {
    //     if(mem.eql(u8, "Function", uobj.class.namestr()[0.."Function".len])) {
    //         // if(mem.eql(u8, "IsGravelyInjured", uobj.namestr()[0.."IsGravelyInjured".len])) {
    //             var ufunc = @ptrCast(*UFunction, uobj);
    //             if(ufunc.iNative != 0) {
    //                 log("(ntl = {d}) {s}::exec{s} = {x};", .{ufunc.iNative, uobj.outer.namestr(), uobj.namestr(), @ptrToInt(ufunc.Func)});            

    //                 // UObject::ProcessInternal
    //             // if(@ptrToInt(ufunc.Func) != 0x4a3b50 and @ptrToInt(ufunc.Func) != 0x0) {
    //                 // log("UObject::GObjObjects[{d}] = {s}:{s} = {x};", .{idx, uobj.namestr(), uobj.class.namestr(), @ptrToInt(ufunc.Func)});            
    //             }
                
    //             // var ufunc = @ptrCast([*]align (1) u32, uobj);
    //             // for(ufunc[0..0x300 / 0x4]) |val, off| {
    //             //     log("{x}: {x}\n", .{off * 0x4, val});
    //             // }
    //         // }
    //     }
    //     // if(uobj.class == null) log("UObject::GObjObjects[{d}] = {s}:NULLCLASS\n", .{idx, uobj.namestr()});
    // }

    // // for(gobjs.data[0..100]) |uobj, idx| {
    // //     debug.assert(uobj.class != null);
    // //     log("UObject::GObjObjects[{d}] = {s}:{s}\n", .{idx, uobj.namestr(), uobj.class.?.namestr()});
    // // }

    // // log("UObject::GObjObjects[1] = {x}\n", .{@ptrToInt(gobjs.data[1])});

    // log(":: (FArray) Names ::\n", .{});

    // for(names.slice()[0..5]) |fname, idx| {
    //     log("..Names[{d}] = '{s}'\n", .{idx, fname.utf8_string()});
    // }
    
    // log("...\n", .{});

    // string null byte
    // msg.append(0x0) catch unreachable;
    // log("finished - closing XComEW.exe\n", .{});
    // std.os.exit(0);
    // _ = user32.MessageBoxA(null, @ptrCast([*:0]u8, msg.items.ptr), "muton-injector", 0);
}