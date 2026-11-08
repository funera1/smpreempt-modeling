; Hand-written form matching Clang's optimized pointer/count memset loop.
target datalayout = "e-p:64:64-i64:64-n32:64-S128"
target triple = "riscv64-unknown-elf"
define ptr @fill(ptr %p, i32 %c, i64 %n) {
entry:
  %empty = icmp eq i64 %n, 0
  br i1 %empty, label %exit, label %prepare
prepare:
  %byte = trunc i32 %c to i8
  br label %loop
loop:
  %cursor = phi ptr [ %p, %prepare ], [ %nextptr, %loop ]
  %remaining = phi i64 [ %n, %prepare ], [ %nextcount, %loop ]
  %nextcount = add i64 %remaining, -1
  %nextptr = getelementptr inbounds i8, ptr %cursor, i64 1
  store i8 %byte, ptr %cursor, align 1
  %done = icmp eq i64 %nextcount, 0
  br i1 %done, label %exit, label %loop
exit:
  ret ptr %p
}
