/* Ring-3 entry for the hito-4 user editor (same prologue as user/shell). */
    .section .text.entry, "ax"
    .globl _start
    .type _start, @function
_start:
    cld                         /* SysV ABI: direction flag must be clear */
    andq $-16, %rsp             /* callee sees RSP%16 == 8 after the call */
    call main                   /* main() is `extern "C"` and never returns */

    /* Defensive fallback: if main ever returns, Exit(0) through the gate. */
    movl $1, %eax               /* SYS_EXIT = 1 */
    xorl %edi, %edi
    int $0x80
1:
    hlt
    jmp 1b
    .size _start, .-_start

    .section .note.GNU-stack, "", @progbits
