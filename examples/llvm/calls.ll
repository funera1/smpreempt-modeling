target datalayout = "e-p:64:64-i64:64-n32:64-S128"
target triple = "riscv64-unknown-elf"
define i64 @increment(ptr %p) {
entry:
  %before = load i64, ptr %p, align 8
  %after = add i64 %before, 1
  store i64 %after, ptr %p, align 8
  ret i64 %after
}
define i64 @caller(ptr %p) {
entry:
  %a = call i64 @increment(ptr %p)
  %b = call i64 @increment(ptr %p)
  %sum = add i64 %a, %b
  ret i64 %sum
}
