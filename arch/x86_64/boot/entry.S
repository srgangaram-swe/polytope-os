/*
 * Reserved x86_64 bootstrap boundary. The executable boot protocol and linker
 * integration land in Sprint 2; assembly remains minimal and architecture-local.
 */
.section .text.boot, "ax"
.global axiom_boot_entry
.type axiom_boot_entry, @function
axiom_boot_entry:
    cli
1:  hlt
    jmp 1b
.size axiom_boot_entry, . - axiom_boot_entry

.section .note.GNU-stack, "", @progbits
