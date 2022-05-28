# Exalted

## A native code extension and reverse-engineering toolkit for XCom: Enemy Within 
### Overview

This repo has two goals:
    
1. to serve as source for an equivalent to existing 'dll-injector' native code patchers such as [Ares](https://ares-developers.github.io/Ares-docs/index.html), but applied to the specific variation of Unreal Engine 3 that XCom: Enemy Within runs off.

2. to act as a library for reverse engineering notes on the general workings of Unreal Engine 3, and the specific workings of native C/C++ XCom: Enemy Within code.


### Project layout

```
src/
    - contains zig source for 'exalted' and 'muton' (exalted = injector wrapper, muton = .dll that gets injected)
    src/main.zig
        - 'exalted.exe' main code, handles .dll injection + script attaching + reading stdout/stderr of XComEW.exe
    src/winapi.zig
        - various zig wrappers/interfaces for the win32 API
    src/thread_main.zig
        - 'DllMain' for muton.dll, acts as entrypoint for 'LoadLibraryA'
    src/dll_main.zig
        - core logic for muton.dll
    src/muton/XComEW.zig
        - a zig wrapper for Unreal Engine 3 objects + functions that will be in the memory of an injected 'XComEW.exe'

research/
    - reverse engineering resources (notes + .idapython scripts) for Unreal Engine 3, as well as XComEW itself
    research/ida_scripts/
        - various idapython scripts used various kinds of batch cleaning/reversing of the parent `XComEW.exe` idb
```

### exalted.exe: example usage

Currently usage of `exalted.exe` is handled entirely by `zig build` (this will change in the future to allow for more flexibility wrt. passing arguments/different dll's to inject, etc).

To launch `XCom.exe` and inject a barebones `muton.dll`, do the following:

```
zig build run -Dtarget=i386-windows -DXComEWDirectory='C:\XCOM Enemy Unknown\XEW\Binaries\Win32'
```

Certain build flags can also be passed to `zig build` to control the behaviour of `muton.dll`

```
# Instructs muton.dll to dump 'GNative' (static native function table) and exit
zig build run -Dtarget=i386-windows -DXComEWDirectory='C:\XCOM Enemy Unknown\XEW\Binaries\Win32' -Ddump_GNatives=true
```

By default `exalted.exe` will always inject `muton.dll` into a launched `XComEW.exe` process. However `-Dno_inject=true` can be specified to omit the dll injection phase:

```
# exalted.exe launches XComEW.exe, does no injection, and waits for it to exit
zig build run -Dtarget=i386-windows -DXComEWDirectory='C:\XCOM Enemy Unknown\XEW\Binaries\Win32' -Dno_inject=true
```

The flag `-De_script` specifies a Frida JS script to embed into exalted, to attach to XComEW once it launches:

```
zig build run -Dtarget=i386-windows -DXComEWDirectory='C:\XCOM Enemy Unknown\XEW\Binaries\Win32' -De_script='example-scripts\uclass_trace.js'
```

This can be combined with `-Dno_inject=true`, for keeping `XComEW.exe` 'pure' for reversing/analysis purposes:

`zig build run -Dtarget=i386-windows -DXComEWDirectory='C:\XCOM Enemy Unknown\XEW\Binaries\Win32' -De_script='example-scripts\uclass_trace.js' -Dno_inject=true`
