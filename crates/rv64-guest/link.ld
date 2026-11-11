OUTPUT_ARCH(riscv)
ENTRY(_start)
SECTIONS
{
    . = 0x80000000;
    .text : ALIGN(4) { KEEP(*(.text.start)) *(.text .text.*) . = ALIGN(4); }
    .rodata : ALIGN(8) { *(.rodata .rodata.* .srodata .srodata.*) }
    .data : ALIGN(8) { *(.data .data.* .sdata .sdata.*) }
    .bss (NOLOAD) : ALIGN(8) { *(.bss .bss.* .sbss .sbss.* COMMON) }
    .image_end : ALIGN(16) { QUAD(0); QUAD(0); }
    __program_end = .;
    __global_pointer$ = __program_end;
    /* 128-byte canary gap, then a 32 MiB stack. */
    __stack_top = __program_end + 128 + 33554432;
    /DISCARD/ : { *(.eh_frame .eh_frame_hdr) }
}
