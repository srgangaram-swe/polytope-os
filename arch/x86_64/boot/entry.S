/*
 * Reserved x86_64 bootstrap boundary. The executable boot protocol and linker
 * integration land in Sprint 2; assembly remains minimal and architecture-local.
 */
.section .text.boot, "ax"
.global polytope_boot_entry
.type polytope_boot_entry, @function
polytope_boot_entry:
    cli
1:  hlt
    jmp 1b
.size polytope_boot_entry, . - polytope_boot_entry

.section .note.GNU-stack, "", @progbits
