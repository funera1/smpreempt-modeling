"""LLVM's MC disassembler C API, without parsing its presentation text."""
import ctypes
import ctypes.util
from functools import lru_cache


class LLVMDisassemblerUnavailable(RuntimeError):
    pass


@lru_cache(maxsize=8)
def _library(requested=None):
    candidates = [requested] if requested else [ctypes.util.find_library('LLVM-20'),
                                                ctypes.util.find_library('LLVM-18')]
    errors = []
    for name in filter(None, candidates):
        try:
            lib = ctypes.CDLL(name)
            for component in ('TargetInfo', 'Target', 'TargetMC', 'Disassembler', 'AsmPrinter'):
                init = getattr(lib, 'LLVMInitializeRISCV'+component)
                init.argtypes, init.restype = [], None
                init()
            lib.LLVMCreateDisasmCPUFeatures.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
            lib.LLVMCreateDisasmCPUFeatures.restype = ctypes.c_void_p
            lib.LLVMDisasmInstruction.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_uint64, ctypes.c_uint64, ctypes.c_char_p, ctypes.c_size_t]
            lib.LLVMDisasmInstruction.restype = ctypes.c_size_t
            lib.LLVMDisasmDispose.argtypes = [ctypes.c_void_p]
            lib.LLVMDisasmDispose.restype = None
            return lib, name
        except (OSError, AttributeError) as exc:
            errors.append(f'{name}: {exc}')
    raise LLVMDisassemblerUnavailable('LLVM RISC-V disassembler unavailable: '+('; '.join(errors) or 'library not found'))


class LLVMDisassembler:
    def __init__(self, library=None, features='+m,+a,+f,+d,+c,+zicsr,+zifencei'):
        self.lib, self.library = _library(library)
        self.features = features
        self.context = self.lib.LLVMCreateDisasmCPUFeatures(b'riscv64-unknown-elf',
            b'generic-rv64', features.encode(), None, 0, None, None)
        if not self.context:
            raise LLVMDisassemblerUnavailable('cannot create LLVM RISC-V disassembler')

    def decode(self, raw, address):
        data = (ctypes.c_uint8 * len(raw)).from_buffer_copy(raw)
        output = ctypes.create_string_buffer(512)
        size = self.lib.LLVMDisasmInstruction(self.context, data, len(raw), address, output, len(output))
        return int(size), output.value.decode('utf-8', errors='replace').strip()

    def close(self):
        if self.context:
            self.lib.LLVMDisasmDispose(self.context)
            self.context = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
