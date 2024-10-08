/* Useful links:
 * https://wiki.osdev.org/Linker_Scripts
 * https://interrupt.memfault.com/blog/how-to-write-linker-scripts-for-firmware
 * https://refspecs.linuxbase.org/elf/elf.pdf
 * https://ftp.gnu.org/old-gnu/Manuals/ld-2.9.1/html_chapter/ld_3.html#SEC6
 * http://www.bravegnu.org/gnu-eprog/linker.html
 * https://blog.thea.codes/the-most-thoroughly-commented-linker-script/
 * https://sourceware.org/binutils/docs/ld/Builtin-Functions.html
 */

/* Set entrypoint to the firmware in the elf header
 * used by a debugger using the .elf, but the vector table entry to Reset_Handler is
 * what actually indictates the entry point when running on hardware */
ENTRY(Reset_Handler);

/* Identify the memory regions in the memory map (address space) */
MEMORY {
    flash(rx) : ORIGIN = 0x08000000, LENGTH = 512k
    sram(rwx) : ORIGIN = 0x20000000, LENGTH = 128k
}

/* Old Method:
 * Creates a symbol _estack at the end of the RAM memory region. This will be
 * the initial value of the stack (estack means end of the stack) */
/* __stack_end__ = ORIGIN(sram) + LENGTH(sram); */    /* stack points to end of SRAM */

/* Adjust stack size as needed */
STACK_SIZE = 512;

/* Indicate the order of the sections in the flash memory */
SECTIONS {
    /* i.e. Vector table must go first
     * KEEP means that the section must exist even if there are no referenced symbols in it.
     * KEEP is normally used in arm for the vector table */
    .vectors  : { KEEP(*(.vectors)) }   > flash
    /* text is source code */
    .text     : { *(.text*) }           > flash
    /* Read only data (i.e non writeable) */
    .rodata   : { *(.rodata*) }         > flash


    /* Put the stack at the beginning of sram, so a stack overflow triggers a
     * hardfault by accessing invalid memory (and not overwriting the data/bss
     * sections */
    .stack : {
        __stack_start__ = .;
        . = . + STACK_SIZE;
        . = ALIGN(4);
        __stack_end__ = .;
    } > sram

    /* Data section (i.e. initialised, modifiable)
     * sdata and edata symbols can be used to copy data section to ram in the reset function */
    .data : {
        __data_start__ = .;   /* .data section start */
        *(.first_data)
        *(.data SORT(.data.*))
        __data_end__ = .;  /* .data section end */
    } > sram AT > flash
    /*       ^ The AT keyword allows the section to specify the load address
     *       where the section is loaded at runtime, see
     *       https://sourceware.org/binutils/docs/ld/Output-Section-LMA.html */

    /* sidata is a symbol representing the load address of the data section.
     * This is used to copy the data into ram on startup */
    _sidata = LOADADDR(.data);

    /* Bss (i.e. uninitialised, modifiable)
     * sbss and ebss can be used to zero the content of the bss section in the
     * reset function */
    .bss : {
        __bss_start__ = .;              /* .bss section start */
        /* COMMON is a legacy symbol that refers to global variables without an initialiser in C
         * SORT indicates to sort the symbols before placing them in the section */
        *(.bss SORT(.bss.*) COMMON)
        __bss_end__ = .;              /* .bss section end */
    } > sram

    . = ALIGN(8);
    _exit = .;     /* for cmsis_gcc.h  */

    /* .debug_abbrev 0 : { *(.debug_abbrev) } */
    /* .debug_aranges 0 : { *(.debug_aranges) } */
    /* .debug_frame 0 : { *(.debug_frame) } */
    /* .debug_info 0 : { *(.debug_info) } */
    /* .debug_line 0 : { *(.debug_line) } */
    /* .debug_loc 0 : { *(.debug_loc) } */
    /* .debug_macinfo 0 : { *(.debug_macinfo) } */
    /* .debug_pubnames 0 : { *(.debug_pubnames) } */
    /* .debug_pubtypes 0 : { *(.debug_pubtypes) } */
    /* .debug_ranges 0 : { *(.debug_ranges) } */
    /* .debug_str 0 : { *(.debug_str) } */
    /* .debug_types 0 : { *(.debug_types) } */

    /* Init Array and Fini Array are Contructor Destructor sections
     * .jcr is some old style constructor section for arm-gcc v6.3
     * These were appearing in the zig build because of linking in the arm-gcc
     * start files, but actually we want -nostartfiles so these don't need to
     * be discarded*/
    /DISCARD/ : {
        *(.init_array)
        *(.fini_array)
        *(.jcr)
    }
}
