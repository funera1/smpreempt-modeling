/* Source examples for: clang --target=riscv64-unknown-elf -S -emit-llvm ...
 * erase.ll is a small hand-written IR fixture, not this file's compiler output.
 */
typedef __SIZE_TYPE__ size_t;

void erase(unsigned char *p, size_t n) {
  for (size_t i = 0; i < n; ++i)
    p[i] = 0;
}

unsigned long validate_and_use(unsigned long *p) {
  unsigned long checked = *p;
  if (checked != 0)
    return 1;
  return *p;
}

void set_permissions(unsigned long cfg) {
  __asm__ volatile ("csrw pmpcfg0, %0\n\tsfence.vma" :: "r"(cfg) : "memory");
}
