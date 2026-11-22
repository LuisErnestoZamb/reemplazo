/* Ring-3 entry for the hello process.
 *
 * The kernel's ELF loader sets RSP to the initial user stack and jumps to
 * e_entry = USER_BASE + 0x1000 = _start. There is no libc and no CRT: this
 * is the whole C-level prologue.
 */
    .section .text.entry, "ax"
    .globl _start
    .type _start, @function
_start:
    cld                         /* SysV ABI: direction flag must be clear */
    andq $-16, %rsp             /* 16-byte align before the call: callee
                                 * sees RSP%16 == 8, as SysV requires */
    call main                   /* main() is `extern "C"` and never returns */

    /* Defensive fallback: if main ever returns, Exit(0) via the same
     * int $0x80 gate. Reached only if main's `-> !` contract changes. */
    movl $1, %eax               /* SYS_EXIT = 1 */
    xorl %edi, %edi             /* code = 0 */
    int $0x80
1:
    hlt
    jmp 1b
    .size _start, .-_start

    .section .note.GNU-stack, "", @progbits
