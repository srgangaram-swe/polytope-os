/*
 * PolytopeOS x86_64 kernel entry.
 *
 * Required incoming state:
 *   - 64-bit long mode with identity mappings for all loaded PT_LOAD ranges.
 *   - System V AMD64 calling convention.
 *   - RDI = bounded boot-contract byte pointer.
 *   - RSI = boot-contract byte length.
 *   - The loader has exited UEFI boot services.
 *
 * Established state:
 *   - maskable interrupts disabled; direction flag cleared;
 *   - RSP points to the linker-reserved, 16-byte-aligned bootstrap stack;
 *   - .bss is zeroed before safe Rust runs;
 *   - the original handoff pointer and length are passed to
 *     polytope_kernel_main in RDI/RSI.
 *
 * The entry never returns. A return from Rust is a deterministic QEMU failure.
 */
.section .text.entry, "ax", @progbits
.global polytope_kernel_entry
.type polytope_kernel_entry, @function
polytope_kernel_entry:
    cli
    cld

    movq %rdi, %r12
    movq %rsi, %r13

    leaq __bootstrap_stack_top(%rip), %rsp
    andq $-16, %rsp
    xorq %rbp, %rbp

    /* Make the retained BSS probe nonzero so a successful boot proves this
     * shim performed the clear instead of inheriting loader-initialized zero. */
    movabsq $0x50544f5342535354, %rax
    movq %rax, polytope_boot_bss_probe(%rip)

    leaq __bss_start(%rip), %rdi
    leaq __bss_end(%rip), %rcx
    subq %rdi, %rcx
    xorl %eax, %eax
    rep stosb
    cmpq $0, polytope_boot_bss_probe(%rip)
    jne .Lbss_clear_failure

    movq %r12, %rdi
    movq %r13, %rsi
    call polytope_kernel_main

    movl $0x23, %eax
    jmp .Lqemu_exit

.Lbss_clear_failure:
    movl $0x22, %eax
.Lqemu_exit:
    movw $0x00f4, %dx
    outl %eax, %dx
1:
    cli
    hlt
    jmp 1b
.size polytope_kernel_entry, . - polytope_kernel_entry

/* Retained canary storage makes the startup zero-initialization contract
 * observable in the emitted ELF even before the kernel has mutable globals. */
.section .bss.boot, "aw", @nobits
.balign 8
.global polytope_boot_bss_probe
polytope_boot_bss_probe:
    .skip 8

.section .note.GNU-stack, "", @progbits
