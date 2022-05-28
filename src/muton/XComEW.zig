//! wrapper for XComEW.exe global structures (+ general Unreal Engine 3 objects)
//!  provides a zig-friendly way to access various data structures
//!  as well as calling certain functions
//! 
//! NOTE: offsets here are based off GOG's XComEW.exe
//!  from "XCOM: Enemy Unknown Complete Pack" 
//!  these offsets may differ for any other XComEW.exe (e.g. Steam)

const std = @import("std");
const debug = std.debug;

pub const UE3 = struct {
    //! zig-friendly representations
    //!  of various 'general' Unreal Engine 3 data structures
    pub const FNameEntry = packed struct {
        field_0x0: u32,
        field_0x4: u32,
        field_0x8: u32, // holds flag as 1 byte (odd = utf16, even = utf8), * 2 to get index
        HashNext: u32,
        stringdata_start: u8,

        pub fn utf8_string(self: *FNameEntry) [*:0]u8 {
            const ptr = @ptrToInt(self);
            return @intToPtr([*:0]u8, ptr + @offsetOf(FNameEntry, "stringdata_start"));
        }
    };

    pub const FName = packed struct {
        index: u32,
        suffix: u32,

        pub fn entry(self: FName) *FNameEntry {
            return FNames__Names.slice()[self.index];
        }
    };

    pub const UObject = packed struct {
        vtable: u32,
        internal_index: u32,
        _unknown: [0x20]u8,
        outer: *UObject,
        fname: FName,
        class: *UObject,
        _unknown1: [0x4]u8,

        pub fn namestr(self: UObject) [*:0]const u8 {
            return self.fname.entry().utf8_string();
        }
    };

    pub const UFunction = packed struct {
        // UObject
        vtable: u32,
        internal_index: u32,
        _unknown: [0x20]u8,
        outer: *UObject,
        fname: FName,
        class: *UObject,
        _unknown1: [0x4]u8,
        // UField
        SuperField: *anyopaque,
        Next: *anyopaque,
        // UStruct
        _unknown2: [0x8]u8,
        children: *anyopaque,
        property_size: u32,
        _unknown3: [0x30]u8,
        _unknown4: [0x2]u8,
        FunctionFlags: u16,
        iNative: u16,
        RepOffset: u16,
        _unknown5: [0x2]u8,
        FriendlyName: FName,
        OperPrecendence: u8,
        NumParms: u8,
        ParmsSize: u16,
        ReturnValueOffset: u16,
        FirstStructWithDefaults: *anyopaque,
        Func: *anyopaque,
    };

    pub fn FArray(comptime T: type) type {
        return packed struct {
            const Self = @This();

            data: [*]T,
            length: u32,
            capacity: u32,

            pub fn slice(self: *Self) []T {
                return self.data[0..self.length];
            }
        };
    }

    pub fn TMap(comptime KeyType: type, comptime ValueType: type) type {
        const FPair = packed struct {
            key: KeyType,
            value: ValueType,
        };

        const SparseEntry = packed struct {
            pair: FPair,
            NextFreeIndex: u32,
            PrevFreeIndex: u32,
        };

        return packed struct {
            elements: FArray(SparseEntry),
            AllocationFlags: [28]u8,
            FirstFreeIndex: u32,
            NumFreeIndices: u32,
            Hash_low: u32,
            Hash_high: u32,
            HashSize: u32,

            const EntryIterator = struct {
                idx: u32 = 0,
                items: []SparseEntry,

                fn next(self: *@This()) ?*SparseEntry {
                    if(self.idx >= self.items.len) return null;
                    var e = &self.items[self.idx];
                    self.idx += 1;
                    return e;
                }
            };

            pub fn entryIterator(self: *@This()) EntryIterator {
                return EntryIterator{
                    .items = self.elements.slice(),
                };
            }
        };
    }

    comptime {
        debug.assert(@sizeOf(TMap(*anyopaque, *anyopaque)) == 0x3C);
    }

    const FNativeFunctionLookup = packed struct {
        const Item = packed struct {
            cstr: [*:0]u8,
            fptr: *anyopaque,
        };

        items: [*]Item,

        const Iterator = struct {
            idx: u32 = 0,
            items: [*]Item,

            pub fn next(self: *@This()) ?*Item {
                var cur_item = &self.items[self.idx];
                if(@ptrToInt(cur_item.cstr) == 0 or @ptrToInt(cur_item.fptr) == 0) return null;
                self.idx += 1;
                return cur_item;
            }
        };

        pub fn iterator(self: *FNativeFunctionLookup) Iterator {
            return Iterator{.items = self.items};        
        }
    };
};

pub const GNatives = struct {
    const num_entries = 1024;
    const ptr: [*]*anyopaque = @intToPtr([*]*anyopaque, 0x01C6FD70);

    pub fn slice() []*anyopaque {
        return ptr[0..num_entries];
    }
};

pub const FNames__Names = @intToPtr(*UE3.FArray(*UE3.FNameEntry), 0x1CFEF90);

pub const GObjectObjs = @intToPtr(*UE3.FArray(*UE3.UObject), 0x1CFEFC0);

pub const GNativeLookupFuncs = @intToPtr(*UE3.TMap(UE3.FName, UE3.FNativeFunctionLookup), 0x01C73E0C);