"""Small, read-only ctypes binding to the LLVM 18/20 C API.

LLVM owns parsing and verification; this is not a textual LLVM IR parser.
No compilation, optimization, execution, or LLVM target initialization occurs.
"""
import ctypes as C
from ctypes.util import find_library
import os
from pathlib import Path


class LLVMUnavailable(RuntimeError):
    pass


class LLVM:
    def __init__(self, library=None):
        explicit = library or os.environ.get('SMPREEMPT_LIBLLVM')
        candidates = [explicit] if explicit else [find_library('LLVM-20'), find_library('LLVM-18')]
        errors = []
        for name in filter(None, candidates):
            try:
                self.lib = C.CDLL(name)
                self.library = name
                break
            except OSError as exc:
                errors.append(str(exc))
        else:
            raise LLVMUnavailable('libLLVM 18 or 20 is required; use --llvm-library or '
                                  'SMPREEMPT_LIBLLVM. ' + '; '.join(errors))
        p, u, n, i, s = C.c_void_p, C.c_uint, C.c_size_t, C.c_int, C.c_char_p
        self._bind('LLVMGetVersion', None, C.POINTER(u), C.POINTER(u), C.POINTER(u))
        version = [u(), u(), u()]
        self.LLVMGetVersion(*(C.byref(v) for v in version))
        self.version = '.'.join(str(v.value) for v in version)
        if version[0].value not in (18, 20):
            raise LLVMUnavailable(f'unsupported LLVM version {self.version}; use LLVM 18 or 20')
        bindings = {
            'LLVMContextCreate': (p,), 'LLVMContextDispose': (None, p),
            'LLVMCreateMemoryBufferWithMemoryRangeCopy': (p, s, n, s),
            'LLVMDisposeMemoryBuffer': (None, p),
            'LLVMParseIRInContext': (i, p, p, C.POINTER(p), C.POINTER(p)),
            'LLVMParseBitcodeInContext2': (i, p, p, C.POINTER(p)),
            'LLVMWriteBitcodeToFile': (i, p, s),
            'LLVMVerifyModule': (i, p, i, C.POINTER(p)),
            'LLVMDisposeModule': (None, p), 'LLVMDisposeMessage': (None, p),
            'LLVMLinkModules2': (i, p, p),
            'LLVMGetTarget': (s, p), 'LLVMGetDataLayoutStr': (s, p),
            'LLVMPrintModuleToString': (p, p),
            'LLVMGetFirstFunction': (p, p), 'LLVMGetNextFunction': (p, p),
            'LLVMGetFirstGlobal': (p, p), 'LLVMGetNextGlobal': (p, p),
            'LLVMGetInitializer': (p, p), 'LLVMGlobalGetValueType': (p, p),
            'LLVMIsGlobalConstant': (i, p),
            'LLVMGetFirstParam': (p, p), 'LLVMGetNextParam': (p, p),
            'LLVMGetFirstBasicBlock': (p, p), 'LLVMGetNextBasicBlock': (p, p),
            'LLVMGetBasicBlockTerminator': (p, p), 'LLVMBasicBlockAsValue': (p, p),
            'LLVMGetFirstInstruction': (p, p), 'LLVMGetNextInstruction': (p, p),
            'LLVMGetInstructionOpcode': (u, p), 'LLVMGetNumOperands': (i, p),
            'LLVMGetOperand': (p, p, u), 'LLVMTypeOf': (p, p),
            'LLVMGetTypeKind': (u, p), 'LLVMGetIntTypeWidth': (u, p),
            'LLVMGetPointerAddressSpace': (u, p),
            'LLVMGetReturnType': (p, p), 'LLVMIsFunctionVarArg': (i, p),
            'LLVMGetEnumAttributeKindForName': (u, s, n),
            'LLVMGetEnumAttributeAtIndex': (p, p, u, u),
            'LLVMGetCallSiteEnumAttribute': (p, p, u, u),
            'LLVMGetFunctionCallConv': (u, p), 'LLVMGetInstructionCallConv': (u, p),
            'LLVMGetValueName2': (p, p, C.POINTER(n)),
            'LLVMPrintTypeToString': (p, p), 'LLVMPrintValueToString': (p, p),
            'LLVMGetNumSuccessors': (u, p), 'LLVMGetSuccessor': (p, p, u),
            'LLVMIsConditional': (i, p), 'LLVMGetCondition': (p, p),
            'LLVMGetICmpPredicate': (u, p),
            'LLVMCountIncoming': (u, p), 'LLVMGetIncomingValue': (p, p, u),
            'LLVMGetIncomingBlock': (p, p, u),
            'LLVMGetAlignment': (u, p), 'LLVMGetVolatile': (i, p),
            'LLVMGetOrdering': (u, p), 'LLVMGetNUW': (i, p),
            'LLVMGetNSW': (i, p), 'LLVMGetExact': (i, p),
            'LLVMGetNNeg': (i, p), 'LLVMGetIsDisjoint': (i, p),
            'LLVMGetGEPSourceElementType': (p, p), 'LLVMIsInBounds': (i, p),
            'LLVMGetAllocatedType': (p, p),
            'LLVMGetCalledValue': (p, p), 'LLVMGetNumArgOperands': (u, p),
            'LLVMGetArgOperand': (p, p, u),
            'LLVMGetInlineAsmAsmString': (p, p, C.POINTER(n)),
            'LLVMGetInlineAsmConstraintString': (p, p, C.POINTER(n)),
            'LLVMGetInlineAsmHasSideEffects': (i, p),
            'LLVMGetDebugLocFilename': (p, p, C.POINTER(u)),
            'LLVMGetDebugLocDirectory': (p, p, C.POINTER(u)),
            'LLVMGetDebugLocLine': (u, p), 'LLVMGetDebugLocColumn': (u, p),
            'LLVMIsAConstantInt': (p, p), 'LLVMIsAConstantExpr': (p, p),
            'LLVMIsAInlineAsm': (p, p), 'LLVMIsAFunction': (p, p),
            'LLVMIsUndef': (i, p), 'LLVMIsPoison': (i, p),
            'LLVMCreateTargetData': (p, s), 'LLVMDisposeTargetData': (None, p),
            'LLVMTypeIsSized': (i, p), 'LLVMStoreSizeOfType': (C.c_ulonglong, p, p),
            'LLVMABISizeOfType': (C.c_ulonglong, p, p),
            'LLVMGetElementType': (p, p), 'LLVMCountStructElementTypes': (u, p),
            'LLVMGetArrayLength': (u, p),
            'LLVMStructGetTypeAtIndex': (p, p, u),
            'LLVMOffsetOfElement': (C.c_ulonglong, p, p, u),
            'LLVMConstIntGetZExtValue': (C.c_ulonglong, p),
        }
        for name, (result, *args) in bindings.items():
            self._bind(name, result, *args)
        if hasattr(self.lib, 'LLVMGEPGetNoWrapFlags'):
            self._bind('LLVMGEPGetNoWrapFlags', u, p)

    def _bind(self, name, result, *args):
        try:
            function = getattr(self.lib, name)
        except AttributeError as exc:
            raise LLVMUnavailable(f'{self.library} lacks required C API {name}') from exc
        function.restype, function.argtypes = result, list(args)
        setattr(self, name, function)

    @staticmethod
    def chain(first, next_item, parent):
        value = first(parent)
        while value:
            yield value
            value = next_item(value)

    def name(self, value):
        size = C.c_size_t()
        address = self.LLVMGetValueName2(value, C.byref(size))
        return C.string_at(address, size.value).decode('utf8', errors='replace') if size.value else ''

    def text(self, function, value):
        address = function(value)
        try:
            return C.string_at(address).decode('utf8', errors='replace').strip()
        finally:
            self.LLVMDisposeMessage(address)

    def string(self, function, value, size_type=C.c_size_t):
        size = size_type()
        address = function(value, C.byref(size))
        return C.string_at(address, size.value).decode('utf8', errors='replace') if size.value else ''

    def module(self, path, context=None):
        return Module(self, path, context)


class Module:
    def __init__(self, api, path, context=None):
        self.api, self.path = api, str(path)
        self.data = Path(path).read_bytes()
        self.context, self.value = None, None
        self.owns_context = context is None
        if not self.data:
            raise ValueError('empty LLVM input')
        self.context = api.LLVMContextCreate() if context is None else context
        buffer = api.LLVMCreateMemoryBufferWithMemoryRangeCopy(self.data, len(self.data), os.fsencode(path))
        module, message = C.c_void_p(), C.c_void_p()
        try:
            if self.data.startswith((b'BC\xc0\xde', b'\xde\xc0\x17\x0b')):
                try:
                    failed = api.LLVMParseBitcodeInContext2(self.context, buffer, C.byref(module))
                finally:
                    api.LLVMDisposeMemoryBuffer(buffer)
            else:
                # LLVMParseIRInContext takes ownership of the memory buffer.
                failed = api.LLVMParseIRInContext(self.context, buffer, C.byref(module), C.byref(message))
            self.value = module.value
            if failed:
                detail = C.string_at(message).decode('utf8', errors='replace') if message.value else 'invalid LLVM bitcode'
                raise ValueError(detail.strip())
            if message.value:
                api.LLVMDisposeMessage(message)
                message = C.c_void_p()
            # LLVMReturnStatusAction = 2: report invalid IR, never abort here.
            if api.LLVMVerifyModule(self.value, 2, C.byref(message)):
                raise ValueError(C.string_at(message).decode('utf8', errors='replace').strip())
        except BaseException:
            self.close()
            raise
        finally:
            if message.value:
                api.LLVMDisposeMessage(message)

    def close(self):
        if self.value:
            self.api.LLVMDisposeModule(self.value)
            self.value = None
        if self.context:
            if self.owns_context:
                self.api.LLVMContextDispose(self.context)
            self.context = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
