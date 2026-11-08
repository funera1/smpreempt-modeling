/* Concrete base-PMP smoke comparison. This is not Keystone firmware. */
.option norvc
.section .text
.globl _start
.type _start,@function
_start:
    li a4, 0x2000
    csrw pmpaddr0, a4
    li a4, 0x1f
    csrw pmpcfg0, a4

    /* The three PMP operations match the entry-zero pmp_unset sequence. */
    li a4, 0
    csrr a5, pmpcfg0
    andi a5, a5, -256
    csrw pmpaddr0, a4
    csrw pmpcfg0, a5
    sfence.vma
.globl comparison_done
comparison_done:
    ret
.size _start, .-_start
