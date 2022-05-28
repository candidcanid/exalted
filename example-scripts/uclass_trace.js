
console.log("<trace.js active>");

const UClass_UClass = ptr("0x0043D8C0"); 
const mb_appMalloc = ptr("0x00C8FA90"); 

const off_InSize = 0x8;
const off_InNameStr = 0x14;
const off_InPackageName = 0x18;
const off_InClassConstructor = 0x28;
const off_InClassStaticConstructor = 0x2c;
const off_InClassStaticInitializer = 0x2c;

let state = [];

let alloc_map = {};
let alloc_stack = [];

/*
    script that pulls out 'native' UClass constructor, size, name
        based on calls to UClass::UClass (static-class func?)

    _DWORD *__thiscall mb_UClass::UClass(
        _DWORD *this,
        int formal,
        int InSize,
        int InClassFlags,
        int InClassCastFlags,
        WCHAR *InNameStr,
        WCHAR *InPackageName,
        WCHAR *InConfigName,
        int InFlags,
        int InFlagsHigh,
        void *InClassConstructor,
        void *InClassStaticConstructor,
        void *InClassStaticInitializer
    )
*/

Interceptor.attach(UClass_UClass, { 
    onEnter: function (args) {
        // matching mb_UClass_UClass call structure (__thiscall), pulling out arguments
        state.push({
            thisobj: this.context.ecx,
            InNameStr: this.context.esp.add(off_InNameStr).readPointer().readUtf16String(),
            InSize: this.context.esp.add(off_InSize).readPointer(),
            InClassConstructor: this.context.esp.add(off_InClassConstructor).readPointer(),
            InClassStaticConstructor: this.context.esp.add(off_InClassStaticConstructor).readPointer(),
            InClassStaticInitializer: this.context.esp.add(off_InClassStaticInitializer).readPointer(),
        });
    },

    // When function is finished
    onLeave: function (retval) {
        let uclass = state.pop();
        uclass.vtable = uclass.thisobj.readPointer();
        console.log(`
UClass("${uclass.InNameStr}")
..vtable=(UClass) ${uclass.vtable}
..InSize=${uclass.InSize}
..InClassConstructor=${uclass.InClassConstructor}
..InClassStaticConstructor=${uclass.InClassStaticConstructor}
..InClassStaticInitializer=${uclass.InClassStaticInitializer}
`.trim())
    }
});
