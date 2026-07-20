OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(polytope_kernel_entry)

KERNEL_BASE = 0x04000000;
KERNEL_LOAD_LIMIT = 0x04800000;
KERNEL_STACK_GUARD_BASE = 0x047ff000;
KERNEL_STACK_BASE = 0x04800000;
KERNEL_STACK_SIZE = 0x00010000;
PAGE_SIZE = 0x1000;

PHDRS
{
    text PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
    stack PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = KERNEL_BASE;
    __kernel_start = .;

    .text ALIGN(PAGE_SIZE) :
    {
        __text_start = .;
        KEEP(*(.text.entry))
        *(.text .text.*)
        __text_end = .;
    } :text

    .rodata ALIGN(PAGE_SIZE) :
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
        __rodata_end = .;
    } :rodata

    .data ALIGN(PAGE_SIZE) :
    {
        __data_start = .;
        *(.data .data.*)
        *(.got .got.*)
        __data_end = .;
    } :data

    .bss ALIGN(PAGE_SIZE) (NOLOAD) :
    {
        __bss_start = .;
        KEEP(*(.bss.boot))
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } :data

    __kernel_load_end = ALIGN(PAGE_SIZE);
    ASSERT(__kernel_load_end <= KERNEL_STACK_GUARD_BASE,
           "kernel load segments overlap the bootstrap-stack guard")

    . = KERNEL_STACK_GUARD_BASE;
    .stack_guard (NOLOAD) :
    {
        __bootstrap_stack_guard_start = .;
        . += PAGE_SIZE;
        __bootstrap_stack_guard_end = .;
    } :NONE

    . = KERNEL_STACK_BASE;
    .stack ALIGN(PAGE_SIZE) (NOLOAD) :
    {
        __bootstrap_stack_bottom = .;
        . += KERNEL_STACK_SIZE;
        __bootstrap_stack_top = .;
    } :stack

    __kernel_end = ALIGN(PAGE_SIZE);

    /DISCARD/ :
    {
        *(.comment)
        *(.eh_frame .eh_frame.*)
        *(.note .note.*)
    }

    ASSERT((__kernel_start % PAGE_SIZE) == 0, "kernel base must be page aligned")
    ASSERT((__text_start % PAGE_SIZE) == 0, ".text must be page aligned")
    ASSERT((__rodata_start % PAGE_SIZE) == 0, ".rodata must be page aligned")
    ASSERT((__data_start % PAGE_SIZE) == 0, ".data must be page aligned")
    ASSERT((__bss_start % PAGE_SIZE) == 0, ".bss must be page aligned")
    ASSERT(__text_end <= __rodata_start, ".text overlaps .rodata")
    ASSERT(__rodata_end <= __data_start, ".rodata overlaps .data")
    ASSERT(__data_end <= __bss_start, ".data overlaps .bss")
    ASSERT((__bootstrap_stack_bottom % PAGE_SIZE) == 0,
           "bootstrap stack must be page aligned")
    ASSERT((__bootstrap_stack_top - __bootstrap_stack_bottom) == KERNEL_STACK_SIZE,
           "bootstrap stack has an unexpected size")
    ASSERT((__bootstrap_stack_guard_end - __bootstrap_stack_guard_start) == PAGE_SIZE,
           "bootstrap-stack guard reservation must be one page")
    ASSERT(__bootstrap_stack_guard_start == KERNEL_STACK_GUARD_BASE,
           "bootstrap-stack guard start drifted from the loader contract")
    ASSERT(__bootstrap_stack_guard_end == KERNEL_LOAD_LIMIT,
           "kernel load limit must end at the bootstrap stack")
    ASSERT(KERNEL_LOAD_LIMIT == KERNEL_STACK_BASE,
           "kernel load limit and stack base must match")
}
