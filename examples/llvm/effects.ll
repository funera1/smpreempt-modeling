; Hand-written fixtures for effects that must not disappear or become atomic.
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "riscv64-unknown-elf"
declare void @llvm.memset.p0.i64(ptr nocapture writeonly, i8, i64, i1 immarg)
declare i64 @external(ptr)

define i64 @effects(ptr %p, i64 %n, i64 %cfg) {
entry:
  call void @llvm.memset.p0.i64(ptr %p, i8 0, i64 %n, i1 false)
  call void asm sideeffect "csrw pmpcfg0, $0\0A\09sfence.vma", "r,~{memory}"(i64 %cfg)
  %v = load volatile i64, ptr %p, align 8
  %r = call i64 @external(ptr %p)
  %sum = add i64 %v, %r
  ret i64 %sum
}
