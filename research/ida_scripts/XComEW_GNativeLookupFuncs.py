# cmd for idapython console: 
#  exec(open(".../idb/XComEW_GNativeLookupFuncs.py").read())

import logging

import idc
import idaapi
import idautils
import ida_lines
import ida_hexrays
import ida_xref
from json import loads, dumps

from re import search, finditer, DOTALL, MULTILINE, sub

mb_TMap_addEntry = 0x00B51310
mb_wrapper_TMap_addEntry = 0x00636100
mb_FName_lookup = 0x00B1D520
GNativeLookupFuncs = 0x01C73E0C

# GNativeLookup_init_funcs found using following snippet:
"""
call_refs = [addr for addr in idautils.DataRefsTo(GNativeLookupFuncs)]
for func_ea in idautils.Functions():
    func = idaapi.get_func(func_ea)

    for cref_ea in call_refs:
        if func.start_ea <= cref_ea and cref_ea <= func.end_ea:
            GNativeLookup_init_funcs.add(func_ea)

print(dumps([func_ea for func_ea in GNativeLookup_init_funcs]))
"""
GNativeLookup_init_funcs = [0x481860, 0xfb3300, 0x137db00, 0x4360f0, 0xc04010, 0x5f0d90, 0xd4b170, 0xdb3810, 0xefec30, 0xf1f150]

class AnalysisError(RuntimeError):
    pass

def setLvarName(func_ea, lvar, name):
    lsi = ida_hexrays.lvar_saved_info_t()
    lsi.ll = lvar
    lsi.name = name
    ida_hexrays.modify_user_lvar_info(func_ea, ida_hexrays.MLI_NAME, lsi)

class FuncAnalysis(idaapi.ctree_visitor_t):
    def __init__(self, func_ea, cfunc):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.func_ea = func_ea
        self.cfunc = cfunc
    
    def visit_expr(self, expr):
        # look for call expressions...
        if expr.op == idaapi.cot_call:
            # that call 'mb_TMap_addEntry'
            if expr.x.op == idaapi.cot_obj and expr.x.obj_ea == mb_TMap_addEntry:
                # function signature of 'mb_TMap_addEntry'
                """
                    _DWORD *__thiscall mb_TMap_addEntry(
                        _DWORD *this, 
                        _DWORD *retval, 
                        FPair_FName_FNativeFunctionLookup *a3, 
                        _DWORD *a4
                    )
                """
                fpair_tif = get_typeinf("FPair_FName_FNativeFunctionLookup")
                if fpair_tif is None:
                    raise AnalysisError(f"(ERROR) could not find tif for '{FPair_FName_FNativeFunctionLookup}'")

                expr_arg_fpair = expr.a[2]
                assert(expr_arg_fpair.op == idaapi.cot_ref)
                assert(expr_arg_fpair.x.op == idaapi.cot_var)

                fpair_var = expr_arg_fpair.x.v.getv()
                if fpair_var.name != "pair":
                    setLvarName(self.func_ea, fpair_var, "pair")

                if fpair_var.type().get_type_name() != "FPair_FName_FNativeFunctionLookup":
                    fpair_var.set_lvar_type(fpair_tif)

        return 0


class FuncAnnotate(idaapi.ctree_visitor_t):
    def __init__(self, func_ea, cfunc):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.func_ea = func_ea
        self.cfunc = cfunc

        self.lvar_fname_map = {}
        self.lvar_pair_map = {}

    def visit_expr(self, expr):
        self.identify_FPair(expr)
        self.identify_General(expr)
        self.annotate_mb_TMap_addEntry(expr)
        self.annotate_mb_wrapper_TMap_addEntry(expr)
        return 0

    def identify_FPair(self, expr):
        # identify assignments like:
        #  pair.key = mb_FName_lookup(v3, (int)"XGCountryTag", 1);
        #  pair.value = &off_1C1C704;
        if expr.op != idaapi.cot_asg:
            return
        
        y_val = expr.y
        if y_val.op == idaapi.cot_cast:
            y_val = y_val.x

        if expr.x.op != idaapi.cot_memref:
            return

        if expr.x.x.v.getv().type().get_type_name() != "FPair_FName_FNativeFunctionLookup":
            return

        lvar = expr.x.x.v.getv()

        # pair.key
        if expr.x.m == 0x0:
            call_expr = y_val
            
            if call_expr.x.op != idaapi.cot_obj or call_expr.x.obj_ea != mb_FName_lookup:
                return
            
            NameStr_ea = call_expr.a[1].ea
            NameStr_addr_ea = idc.get_operand_value(NameStr_ea, 0)

            NameStr_value = idc.get_strlit_contents(NameStr_addr_ea, -1, idc.STRTYPE_C).decode("utf-8")

            hits = []
            for [idx, sid, name] in idautils.Structs():
                if NameStr_value == name:
                    hits.append([sid, name])
                elif (len(NameStr_value) == len(name) - 1) and name.endswith(NameStr_value):
                    hits.append([sid, name])
            
            assert(len(hits) == 1)
            [uclass_sid, uclass_name] = hits[0]

            self.lvar_pair_map[f"{lvar.name}.key"] = [NameStr_value, uclass_name, uclass_sid]
            print(f"{lvar.name}.key = {uclass_name}")

        # pair.value    
        else:
            assert(expr.x.m == 0x4)
            assert(y_val.op == idaapi.cot_ref)
            self.lvar_pair_map[f"{lvar.name}.value"] = y_val.x.obj_ea
            print(f"{lvar.name}.value = {y_val.x.obj_ea:x}")

    def identify_General(self, expr):
        if expr.op != idaapi.cot_asg:
            return
        
        y_val = expr.y
        if y_val.op == idaapi.cot_cast:
            y_val = y_val.x

        # walking down list of expressions, and identifying FName lookups
        if expr.x.op != idaapi.cot_var or y_val.op != idaapi.cot_call:
            return

        var_expr = expr.x.v
        call_expr = y_val

        hits = []

        if call_expr.x.op == idaapi.cot_obj and call_expr.x.obj_ea == mb_FName_lookup:
            NameStr_ea = call_expr.a[1].ea
            NameStr_addr_ea = idc.get_operand_value(NameStr_ea, 0)

            NameStr_value = idc.get_strlit_contents(NameStr_addr_ea, -1, idc.STRTYPE_C).decode("utf-8")

            hits = []
            for [idx, sid, name] in idautils.Structs():
                if NameStr_value == name:
                    hits.append([sid, name])
                elif (len(NameStr_value) == len(name) - 1) and name.endswith(NameStr_value):
                    hits.append([sid, name])
            
            assert(len(hits) == 1)
            [uclass_sid, uclass_name] = hits[0]

            # print(f"FName({NameStr_value}) maps to {uclass_name}")
            fname_var = var_expr.getv()
            # record this FName lookup call as most recent assignment to this lvar
            self.lvar_fname_map[fname_var.name] = [NameStr_value, uclass_name, uclass_sid]

    # maps identified FPair constructors to mb_TMap_addEntry
    def annotate_mb_TMap_addEntry(self, expr):
        if expr.op != idaapi.cot_call:
            return

        call_expr = expr

        # that call 'mb_TMap_addEntry(GNativeLookupFuncs, ...)'
        if expr.x.op != idaapi.cot_obj or expr.x.obj_ea != mb_TMap_addEntry:
            return

        if call_expr.a[0].op != idaapi.cot_ref or call_expr.a[0].x.obj_ea != GNativeLookupFuncs:
            return

        if call_expr.a[2].op != idaapi.cot_ref:
            return

        pair_lvar = call_expr.a[2].x.v.getv()

        [NameStr_value, uclass_name, uclass_sid] = self.lvar_pair_map[f"{pair_lvar.name}.key"]
        FNativeFunctionLookup_ea = self.lvar_pair_map[f"{pair_lvar.name}.value"]

        self.execAnnotate(NameStr_value, uclass_name, uclass_sid, FNativeFunctionLookup_ea)

    # maps identified FName to TMap FPair constructor func
    def annotate_mb_wrapper_TMap_addEntry(self, expr):
        if expr.op != idaapi.cot_call:
            return

        call_expr = expr

        # that call 'mb_wrapper_TMap_addEntry(GNativeLookupFuncs, ...)'
        if expr.x.op != idaapi.cot_obj or expr.x.obj_ea != mb_wrapper_TMap_addEntry:
            return

        if call_expr.a[0].op != idaapi.cot_ref or call_expr.a[0].x.obj_ea != GNativeLookupFuncs:
            return

        lvar = call_expr.a[1].x.v.getv()
        assert(call_expr.a[2].op == idaapi.cot_ref)
        FNativeFunctionLookup_ea = call_expr.a[2].x.obj_ea

        [NameStr_value, uclass_name, uclass_sid] = self.lvar_fname_map[lvar.name]
        self.execAnnotate(NameStr_value, uclass_name, uclass_sid, FNativeFunctionLookup_ea)

    # apply UClass name and type to FNativeFunctionLookup functions
    def execAnnotate(self, NameStr_value, uclass_name, uclass_sid, FNativeFunctionLookup_ea):
        if idc.get_name(FNativeFunctionLookup_ea).startswith("off_"):
            idc.set_name(FNativeFunctionLookup_ea, f"{uclass_name}Natives")

        entries = []
        for off in range(0x0, 0x3000, 0x8):
            NativeFunc_name_ea = idc.get_wide_dword(FNativeFunctionLookup_ea + off)
            NativeFunc_func_ea = idc.get_wide_dword(FNativeFunctionLookup_ea + off + 0x4)

            if NativeFunc_name_ea == 0x0 or NativeFunc_func_ea == 0x0:
                break
            
            # clean up native function name
            native_func_name = idc.get_strlit_contents(NativeFunc_name_ea, -1, idc.STRTYPE_C).decode("utf-8")
            native_func_name = sub(f"{uclass_name}exec", f"{uclass_name}::exec", native_func_name)

            # print(f"{native_func_name} = {NativeFunc_func_ea:x}")

            # don't update if function has already been named + typed
            if not idc.get_func_name(NativeFunc_func_ea).startswith("sub_"):
                continue

            if idc.get_func_name(NativeFunc_func_ea).startswith("null"):
                continue

            idc.set_name(NativeFunc_func_ea, native_func_name)
            idc.SetType(NativeFunc_func_ea, f"void __thiscall x({uclass_name} *this, FFrame *Stack, void *Result)")

 

def run():
    for func_ea in GNativeLookup_init_funcs:
        try: 
            cfunc = ida_hexrays.decompile(func_ea)
        except ida_hexrays.DecompilationFailure as err:
            print(f"Failed to decompile {func_ea:x}! {str(err)}")
            raise err

        se = FuncAnalysis(func_ea, cfunc)
        se.apply_to(cfunc.body, None)

    for func_ea in GNativeLookup_init_funcs:
        try: 
            cfunc = ida_hexrays.decompile(func_ea)
        except ida_hexrays.DecompilationFailure as err:
            print(f"Failed to decompile {func_ea:x}! {str(err)}")
            raise err
            
        se = FuncAnnotate(func_ea, cfunc)
        se.apply_to(cfunc.body, None)
run()
