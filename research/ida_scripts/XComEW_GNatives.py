# cmd for idapython console: 
#  exec(open(".../XComEW_GNatives.py").read())

import idc
import idaapi
import ida_xref
import idautils
import ida_lines
import ida_hexrays

from re import sub, search

# [GNative table idx, UClass, GNative function]
static = [
    [0, "UObject", "UObject::execLocalVariable"],
    [1, "UObject", "UObject::execInstanceVariable"],
    [2, "UObject", "UObject::execDefaultVariable"],
    [3, "UObject", "UObject::execStateVariable"],
    # NOTE: Return(4) has a special meaning, used as a break
    #  when iterating over UFunction bytecode (in UObject::ProcessInternal)
    # [4, "UObject", "UObject::execReturn"], 
    [5, "UObject", "UObject::execSwitch"],
    [6, "UObject", "UObject::execJump"],
    [7, "UObject", "UObject::execJumpIfNot"],
    [8, "UObject", "UObject::execStop"],
    [9, "UObject", "UObject::execAssert"],
    [10, "UObject", "UObject::execCase"],
    [11, "UObject", "UObject::execNothing"],
    [13, "UObject", "UObject::execGotoLabel"],
    [14, "UObject", "UObject::execEatReturnValue"],
    [15, "UObject", "UObject::execLet"],
    [16, "UObject", "UObject::execDynArrayElement"],
    [17, "UObject", "UObject::execNew"],
    [18, "UObject", "UObject::execClassContext"],
    [19, "UObject", "UObject::execMetaCast"],
    [20, "UObject", "UObject::execLetBool"],
    [22, "UObject", "UObject::execEndFunctionParms"],
    [23, "UObject", "UObject::execSelf"],
    [25, "UObject", "UObject::execContext"],
    [26, "UObject", "UObject::execArrayElement"],
    [27, "UObject", "UObject::execVirtualFunction"],
    [28, "UObject", "UObject::execFinalFunction"],
    [29, "UObject", "UObject::execIntConst"],
    [30, "UObject", "UObject::execFloatConst"],
    [31, "UObject", "UObject::execStringConst"],
    [32, "UObject", "UObject::execObjectConst"],
    [33, "UObject", "UObject::execNameConst"],
    [34, "UObject", "UObject::execRotationConst"],
    [35, "UObject", "UObject::execVectorConst"],
    [36, "UObject", "UObject::execByteConst"],
    [37, "UObject", "UObject::execIntZero"],
    [38, "UObject", "UObject::execIntOne"],
    [39, "UObject", "UObject::execTrue"],
    [40, "UObject", "UObject::execFalse"],
    [41, "UObject", "UObject::execNativeParm"],
    [42, "UObject", "UObject::execNoObject"],
    [44, "UObject", "UObject::execIntConstByte"],
    [45, "UObject", "UObject::execBoolVariable"],
    [46, "UObject", "UObject::execDynamicCast"],
    [47, "UObject", "UObject::execIterator"],
    [48, "UObject", "UObject::execIteratorPop"],
    [50, "UObject", "UObject::execStructCmpEq"],
    [51, "UObject", "UObject::execStructCmpNe"],
    [52, "UObject", "UObject::execUnicodeStringConst"],
    [53, "UObject", "UObject::execStructMember"],
    [54, "UObject", "UObject::execDynArrayLength"],
    [55, "UObject", "UObject::execGlobalFunction"],
    [56, "UObject", "UObject::execPrimitiveCast"],
    [57, "UObject", "UObject::execDynArrayInsert"],
    [58, "UObject", "UObject::execReturnNothing"],
    [59, "UObject", "UObject::execEqualEqual_DelegateDelegate"],
    [60, "UObject", "UObject::execNotEqual_DelegateDelegate"],
    [61, "UObject", "UObject::execEqualEqual_DelegateFunction"],
    [62, "UObject", "UObject::execNotEqual_DelegateFunction"],
    [63, "UObject", "UObject::execEmptyDelegate"],
    [64, "UObject", "UObject::execDynArrayRemove"],
    [65, "UObject", "UObject::execDebugInfo"],
    [66, "UObject", "UObject::execDelegateFunction"],
    [67, "UObject", "UObject::execDelegateProperty"],
    [68, "UObject", "UObject::execLetDelegate"],
    [69, "UObject", "UObject::execConditional"],
    [70, "UObject", "UObject::execDynArrayFind"],
    [71, "UObject", "UObject::execDynArrayFindStruct"],
    [72, "UObject", "UObject::execLocalOutVariable"],
    [73, "UObject", "UObject::execDefaultParmValue"],
    [74, "UObject", "UObject::execEmptyParmValue"],
    [75, "UObject", "UObject::execInstanceDelegate"],
    [81, "UObject", "UObject::execInterfaceContext"],
    [82, "UObject", "UObject::execInterfaceCast"],
    [83, "UObject", "UObject::execEndOfScript"],
    [84, "UObject", "UObject::execDynArrayAdd"],
    [85, "UObject", "UObject::execDynArrayAddItem"],
    [86, "UObject", "UObject::execDynArrayRemoveItem"],
    [87, "UObject", "UObject::execDynArrayInsertItem"],
    [88, "UObject", "UObject::execDynArrayIterator"],
    [89, "UObject", "UObject::execDynArraySort"],
    [90, "UObject", "UObject::execFilterEditorOnly"],
    [96, "UObject", "UObject::execHighNative0"],
    [97, "UObject", "UObject::execHighNative1"],
    [98, "UObject", "UObject::execHighNative2"],
    [99, "UObject", "UObject::execHighNative3"],
    [100, "UObject", "UObject::execHighNative4"],
    [101, "UObject", "UObject::execHighNative5"],
    [102, "UObject", "UObject::execHighNative6"],
    [103, "UObject", "UObject::execHighNative7"],
    [104, "UObject", "UObject::execHighNative8"],
    [105, "UObject", "UObject::execHighNative9"],
    [106, "UObject", "UObject::execHighNative10"],
    [107, "UObject", "UObject::execHighNative11"],
    [108, "UObject", "UObject::execHighNative12"],
    [109, "UObject", "UObject::execHighNative13"],
    [110, "UObject", "UObject::execHighNative14"],
    [111, "UObject", "UObject::execHighNative15"],
    [112, "UObject", "UObject::execConcat_StrStr"],
    [113, "UObject", "UObject::execGotoState"],
    [114, "UObject", "UObject::execEqualEqual_ObjectObject"],
    [115, "UObject", "UObject::execLess_StrStr"],
    [116, "UObject", "UObject::execGreater_StrStr"],
    [117, "UObject", "UObject::execEnable"],
    [118, "UObject", "UObject::execDisable"],
    [119, "UObject", "UObject::execNotEqual_ObjectObject"],
    [120, "UObject", "UObject::execLessEqual_StrStr"],
    [121, "UObject", "UObject::execGreaterEqual_StrStr"],
    [122, "UObject", "UObject::execEqualEqual_StrStr"],
    [123, "UObject", "UObject::execNotEqual_StrStr"],
    [124, "UObject", "UObject::execComplementEqual_StrStr"],
    [125, "UObject", "UObject::execLen"],
    [126, "UObject", "UObject::execInStr"],
    [127, "UObject", "UObject::execMid"],
    [128, "UObject", "UObject::execLeft"],
    [129, "UObject", "UObject::execNot_PreBool"],
    [130, "UObject", "UObject::execAndAnd_BoolBool"],
    [131, "UObject", "UObject::execXorXor_BoolBool"],
    [132, "UObject", "UObject::execOrOr_BoolBool"],
    [133, "UObject", "UObject::execMultiplyEqual_ByteByte"],
    [134, "UObject", "UObject::execDivideEqual_ByteByte"],
    [135, "UObject", "UObject::execAddEqual_ByteByte"],
    [136, "UObject", "UObject::execSubtractEqual_ByteByte"],
    [137, "UObject", "UObject::execAddAdd_PreByte"],
    [138, "UObject", "UObject::execSubtractSubtract_PreByte"],
    [139, "UObject", "UObject::execAddAdd_Byte"],
    [140, "UObject", "UObject::execSubtractSubtract_Byte"],
    [141, "UObject", "UObject::execComplement_PreInt"],
    [142, "UObject", "UObject::execEqualEqual_RotatorRotator"],
    [143, "UObject", "UObject::execSubtract_PreInt"],
    [144, "UObject", "UObject::execMultiply_IntInt"],
    [145, "UObject", "UObject::execDivide_IntInt"],
    [146, "UObject", "UObject::execAdd_IntInt"],
    [147, "UObject", "UObject::execSubtract_IntInt"],
    [148, "UObject", "UObject::execLessLess_IntInt"],
    [149, "UObject", "UObject::execGreaterGreater_IntInt"],
    [150, "UObject", "UObject::execLess_IntInt"],
    [151, "UObject", "UObject::execGreater_IntInt"],
    [152, "UObject", "UObject::execLessEqual_IntInt"],
    [153, "UObject", "UObject::execGreaterEqual_IntInt"],
    [154, "UObject", "UObject::execEqualEqual_IntInt"],
    [155, "UObject", "UObject::execNotEqual_IntInt"],
    [156, "UObject", "UObject::execAnd_IntInt"],
    [157, "UObject", "UObject::execXor_IntInt"],
    [158, "UObject", "UObject::execOr_IntInt"],
    [159, "UObject", "UObject::execMultiplyEqual_IntFloat"],
    [160, "UObject", "UObject::execDivideEqual_IntFloat"],
    [161, "UObject", "UObject::execAddEqual_IntInt"],
    [162, "UObject", "UObject::execSubtractEqual_IntInt"],
    [163, "UObject", "UObject::execAddAdd_PreInt"],
    [164, "UObject", "UObject::execSubtractSubtract_PreInt"],
    [165, "UObject", "UObject::execAddAdd_Int"],
    [166, "UObject", "UObject::execSubtractSubtract_Int"],
    [167, "UObject", "UObject::execRand"],
    [168, "UObject", "UObject::execAt_StrStr"],
    [169, "UObject", "UObject::execSubtract_PreFloat"],
    [170, "UObject", "UObject::execMultiplyMultiply_FloatFloat"],
    [171, "UObject", "UObject::execMultiply_FloatFloat"],
    [172, "UObject", "UObject::execDivide_FloatFloat"],
    [173, "UObject", "UObject::execPercent_FloatFloat"],
    [174, "UObject", "UObject::execAdd_FloatFloat"],
    [175, "UObject", "UObject::execSubtract_FloatFloat"],
    [176, "UObject", "UObject::execLess_FloatFloat"],
    [177, "UObject", "UObject::execGreater_FloatFloat"],
    [178, "UObject", "UObject::execLessEqual_FloatFloat"],
    [179, "UObject", "UObject::execGreaterEqual_FloatFloat"],
    [180, "UObject", "UObject::execEqualEqual_FloatFloat"],
    [181, "UObject", "UObject::execNotEqual_FloatFloat"],
    [182, "UObject", "UObject::execMultiplyEqual_FloatFloat"],
    [183, "UObject", "UObject::execDivideEqual_FloatFloat"],
    [184, "UObject", "UObject::execAddEqual_FloatFloat"],
    [185, "UObject", "UObject::execSubtractEqual_FloatFloat"],
    [186, "UObject", "UObject::execAbs"],
    [187, "UObject", "UObject::execSin"],
    [188, "UObject", "UObject::execCos"],
    [189, "UObject", "UObject::execTan"],
    [190, "UObject", "UObject::execAtan"],
    [191, "UObject", "UObject::execExp"],
    [192, "UObject", "UObject::execLoge"],
    [193, "UObject", "UObject::execSqrt"],
    [194, "UObject", "UObject::execSquare"],
    [195, "UObject", "UObject::execFRand"],
    [196, "UObject", "UObject::execGreaterGreaterGreater_IntInt"],
    [197, "UObject", "UObject::execIsA"],
    [198, "UObject", "UObject::execMultiplyEqual_ByteFloat"],
    [199, "UObject", "UObject::execRound"],
    [201, "UObject", "UObject::execRepl"],
    [203, "UObject", "UObject::execNotEqual_RotatorRotator"],
    [210, "UObject", "UObject::execComplementEqual_FloatFloat"],
    [211, "UObject", "UObject::execSubtract_PreVector"],
    [212, "UObject", "UObject::execMultiply_VectorFloat"],
    [213, "UObject", "UObject::execMultiply_FloatVector"],
    [214, "UObject", "UObject::execDivide_VectorFloat"],
    [215, "UObject", "UObject::execAdd_VectorVector"],
    [216, "UObject", "UObject::execSubtract_VectorVector"],
    [217, "UObject", "UObject::execEqualEqual_VectorVector"],
    [218, "UObject", "UObject::execNotEqual_VectorVector"],
    [219, "UObject", "UObject::execDot_VectorVector"],
    [220, "UObject", "UObject::execCross_VectorVector"],
    [221, "UObject", "UObject::execMultiplyEqual_VectorFloat"],
    [222, "UObject", "UObject::execDivideEqual_VectorFloat"],
    [223, "UObject", "UObject::execAddEqual_VectorVector"],
    [224, "UObject", "UObject::execSubtractEqual_VectorVector"],
    [225, "UObject", "UObject::execVSize"],
    [226, "UObject", "UObject::execNormal"],
    [228, "UObject", "UObject::execVSizeSq"],
    [229, "UObject", "UObject::execGetAxes"],
    [230, "UObject", "UObject::execGetUnAxes"],
    [231, "UObject", "UObject::execLogInternal"],
    [232, "UObject", "UObject::execWarnInternal"],
    [234, "UObject", "UObject::execRight"],
    [235, "UObject", "UObject::execCaps"],
    [236, "UObject", "UObject::execChr"],
    [237, "UObject", "UObject::execAsc"],
    [238, "UObject", "UObject::execLocs"],
    [242, "UObject", "UObject::execEqualEqual_BoolBool"],
    [243, "UObject", "UObject::execNotEqual_BoolBool"],
    [244, "UObject", "UObject::execFMin"],
    [245, "UObject", "UObject::execFMax"],
    [246, "UObject", "UObject::execFClamp"],
    [247, "UObject", "UObject::execLerp"],
    [249, "UObject", "UObject::execMin"],
    [250, "UObject", "UObject::execMax"],
    [251, "UObject", "UObject::execClamp"],
    [252, "UObject", "UObject::execVRand"],
    [253, "UObject", "UObject::execPercent_IntInt"],
    [254, "UObject", "UObject::execEqualEqual_NameName"],
    [255, "UObject", "UObject::execNotEqual_NameName"],
    [256, "AActor", "AActor::execSleep"],
    [258, "UObject", "UObject::execClassIsChildOf"],
    [261, "AActor", "AActor::execFinishAnim"],
    [262, "AActor", "AActor::execSetCollision"],
    [266, "AActor", "AActor::execMove"],
    [267, "AActor", "AActor::execSetLocation"],
    [270, "UObject", "UObject::execAdd_QuatQuat"],
    [271, "UObject", "UObject::execSubtract_QuatQuat"],
    [272, "AActor", "AActor::execSetOwner"],
    [275, "UObject", "UObject::execLessLess_VectorRotator"],
    [276, "UObject", "UObject::execGreaterGreater_VectorRotator"],
    [277, "AActor", "AActor::execTrace"],
    [279, "AActor", "AActor::execDestroy"],
    [280, "AActor", "AActor::execSetTimer"],
    [281, "UObject", "UObject::execIsInState"],
    [283, "AActor", "AActor::execSetCollisionSize"],
    [284, "UObject", "UObject::execGetStateName"],
    [287, "UObject", "UObject::execMultiply_RotatorFloat"],
    [288, "UObject", "UObject::execMultiply_FloatRotator"],
    [289, "UObject", "UObject::execDivide_RotatorFloat"],
    [290, "UObject", "UObject::execMultiplyEqual_RotatorFloat"],
    [291, "UObject", "UObject::execDivideEqual_RotatorFloat"],
    [296, "UObject", "UObject::execMultiply_VectorVector"],
    [297, "UObject", "UObject::execMultiplyEqual_VectorVector"],
    [298, "AActor", "AActor::execSetBase"],
    [299, "AActor", "AActor::execSetRotation"],
    [300, "UObject", "UObject::execMirrorVectorByNormal"],
    [304, "AActor", "AActor::execAllActors"],
    [305, "AActor", "AActor::execChildActors"],
    [306, "AActor", "AActor::execBasedActors"],
    [307, "AActor", "AActor::execTouchingActors"],
    [309, "AActor", "AActor::execTraceActors"],
    [311, "AActor", "AActor::execVisibleActors"],
    [312, "AActor", "AActor::execVisibleCollidingActors"],
    [313, "AActor", "AActor::execDynamicActors"],
    [316, "UObject", "UObject::execAdd_RotatorRotator"],
    [317, "UObject", "UObject::execSubtract_RotatorRotator"],
    [318, "UObject", "UObject::execAddEqual_RotatorRotator"],
    [319, "UObject", "UObject::execSubtractEqual_RotatorRotator"],
    [320, "UObject", "UObject::execRotRand"],
    [321, "AActor", "AActor::execCollidingActors"],
    [322, "UObject", "UObject::execConcatEqual_StrStr"],
    [323, "UObject", "UObject::execAtEqual_StrStr"],
    [324, "UObject", "UObject::execSubtractEqual_StrStr"],
    [384, "AActor", "AActor::execPollSleep"],
    [385, "AActor", "AActor::execPollFinishAnim"],
    [500, "AController", "AController::execMoveTo"],
    [501, "AController", "AController::execPollMoveTo"],
    [502, "AController", "AController::execMoveToward"],
    [503, "AController", "AController::execPollMoveToward"],
    [508, "AController", "AController::execFinishRotation"],
    [509, "AController", "AController::execPollFinishRotation"],
    [511, "AUDKBot", "AUDKBot::execPollWaitToSeeEnemy"],
    [512, "AActor", "AActor::execMakeNoise"],
    [513, "AUDKBot", "AUDKBot::execPollLatentWhatToDoNext"],
    [524, "APlayerController", "APlayerController::execFindStairRotation"],
    [527, "AController", "AController::execWaitForLanding"],
    [528, "AController", "AController::execPollWaitForLanding"],
    [531, "AController", "AController::execPickTarget"],
    [532, "AActor", "AActor::execPlayerCanSeeMe"],
    [533, "AController", "AController::execCanSee"],
    [536, "UObject", "UObject::execSaveConfig"],
    [537, "AController", "AController::execCanSeeByPoints"],
    [546, "APlayerController", "APlayerController::execUpdateURL"],
    [547, "AActor", "AActor::execGetURLMap"],
    [548, "AActor", "AActor::execFastTrace"],
    [999, "AUDKVehicle", "AUDKVehicle::execIsSeatControllerReplicationViewer"],
    [1500, "UObject", "UObject::execProjectOnTo"],
    [1501, "UObject", "UObject::execIsZero"],
    [2511, "UObject", "UObject::execSubtract_PreVector2D"],
    [2513, "UObject", "UObject::execMultiply_FloatVector2D"],
    [2517, "UObject", "UObject::execEqualEqual_Vector2DVector2D"],
    [2518, "UObject", "UObject::execNotEqual_Vector2DVector2D"],
    [2525, "UObject", "UObject::execV2DSize"],
    [2526, "UObject", "UObject::execV2DNormal"],
    [2596, "UObject", "UObject::execMultiply_Vector2DVector2D"],
    [2597, "UObject", "UObject::execMultiplyEqual_Vector2DVector2D"],
    [3969, "AActor", "AActor::execMoveSmooth"],
    [3970, "AActor", "AActor::execSetPhysics"],
    [3971, "AActor", "AActor::execAutonomousPhysics"],
]


GNativeDuplicate = 0x01C73DB4

# native_index: [UClass, NativeFuncName]
static_map = {x[0]: (x[1], x[2]) for x in static}
seen_ntl = set()

class CFuncAnalysis(idaapi.ctree_visitor_t):
    def __init__(self):
        idaapi.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST | ida_hexrays.CV_INSNS)

    def visit_insn(self, insn):
        if insn.op != idaapi.cit_block:
            return 0

        insn_list = list(expr for expr in insn.cblock)
        if len(insn_list) != 2:
            return 0

        for expr in insn_list:
            if expr.op != idaapi.cit_expr:
                return 0

        [first_expr, second_expr] = [insn.cexpr for insn in insn_list]
        # check that first line looks like:
        # result = off_1C06034[0];
        if first_expr.op != idaapi.cot_asg:
            return 0

        if first_expr.x.op != idaapi.cot_var:
            return 0

        mb_idx = first_expr.y
        if mb_idx.op == idaapi.cot_cast:
            mb_idx = mb_idx.x

        if mb_idx.op == idaapi.cot_idx:
            if mb_idx.x.op != idaapi.cot_obj:
                return 0

            if mb_idx.y.op != idaapi.cot_num:
                return 0

            tif = idaapi.tinfo_t()
            tif.get_named_type(idaapi.get_idati(), "uint16_t")
            idx_val = mb_idx.y.n.value(tif)
            if idx_val != 0: 
                return 0

            fobj = mb_idx.x
        else:
            if mb_idx.op != idaapi.cot_obj:
                return 0

            fobj = mb_idx

        # check that second line looks like:
        #  GNativeDuplicate = (some native table idx)
        if second_expr.op != idaapi.cot_asg:
            return 0

        if second_expr.x.op != idaapi.cot_obj:
            return 0

        if second_expr.y.op != idaapi.cot_num:
            return 0

        if second_expr.x.obj_ea != GNativeDuplicate:
            return 0

        tif = idaapi.tinfo_t()
        tif.get_named_type(idaapi.get_idati(), "uint16_t")
        native_index = second_expr.y.n.value(tif)

        func_holder_ea = fobj.obj_ea
        native_func_ea = idc.get_wide_dword(func_holder_ea)

        [uclass, func_name] = static_map[native_index]
        print(f"{func_name} ({native_index}): {native_func_ea}")
        seen_ntl.add(native_index)

        if idc.get_func_name(native_func_ea).startswith("sub_"):
            idc.set_name(native_func_ea, func_name)
            idc.SetType(native_func_ea, f"void __thiscall x({uclass} *this, FFrame *Stack, void *Result)")

        return 0
    

def funcExistsWithName(name):
    loc = idc.get_name_ea_simple(name)
    func = ida_funcs.get_func(loc)
    return func is not None

def identify_GNativeFunction(func, ref_ea):
    try: 
        cfunc = ida_hexrays.decompile(func.start_ea)
    except ida_hexrays.DecompilationFailure as err:
        print(f"Failed to decompile!: {err}")
        return

    se = CFuncAnalysis()
    se.apply_to(cfunc.body, None)


def run():
    refs = [addr for addr in idautils.DataRefsTo(GNativeDuplicate)]
        
    for ref_ea in refs:
        func = idaapi.get_func(ref_ea)
        identify_GNativeFunction(func, ref_ea)

    for nidx, [uclass, func_name] in static_map.items():
        if nidx not in seen_ntl:
            if funcExistsWithName(func_name) is False:
                print(f"missing definition for ({nidx}) {func_name}")
run()