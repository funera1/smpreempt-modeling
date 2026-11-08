"""Link captured LLVM translation units through the LLVM C API."""
import hashlib
from pathlib import Path

from smpreempt.frontend.llvm_c import LLVM


def link_ir(inputs, output, library=None):
    if not inputs:
        raise ValueError('at least one LLVM input is required')
    paths = [Path(p).resolve() for p in inputs]
    output = Path(output).resolve()
    if output in paths:
        raise ValueError('link output must differ from every input')
    api = LLVM(library)
    with api.module(paths[0]) as destination:
        target = api.LLVMGetTarget(destination.value)
        layout = api.LLVMGetDataLayoutStr(destination.value)
        for path in paths[1:]:
            with api.module(path, context=destination.context) as source:
                if api.LLVMGetTarget(source.value) != target or api.LLVMGetDataLayoutStr(source.value) != layout:
                    raise ValueError('cannot link inputs with different targets/datalayouts')
                ptr, source.value = source.value, None  # LLVMLinkModules2 consumes the source, even on failure
                if api.LLVMLinkModules2(destination.value, ptr):
                    raise ValueError('LLVM link failed: '+str(path))
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.suffix == '.bc':
            if api.LLVMWriteBitcodeToFile(destination.value, bytes(output)):
                raise ValueError('failed to write linked bitcode')
        else:
            output.write_text(api.text(api.LLVMPrintModuleToString, destination.value)+'\n')
    return dict(inputs=[dict(path=str(p), sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths],
                output=str(output), sha256=hashlib.sha256(output.read_bytes()).hexdigest(), llvm_version=api.version)
