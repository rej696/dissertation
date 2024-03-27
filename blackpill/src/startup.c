#include "systick.h"

#include <stdint.h>

/* forward declare main function */
extern int main(void);

/* Startup code */
__attribute__((naked, noreturn)) void _reset(void)
{
    /* declare linkerscript symbols */
    extern uint32_t _sbss, _ebss;   /* Start/end of .bss section */
    extern uint32_t _sdata, _edata; /* Start/end of .data section in flash */
    extern uint32_t _sidata;        /* Start of .data section in sram */

    /* set .bss to zero */
    for (uint32_t *dst = &_sbss; dst < &_ebss; ++dst) {
        *dst = 0U;
    }

    for (uint32_t *dst = &_sdata, *src = &_sidata; dst < &_edata; ++dst, ++src) {
        *dst = *src;
    }

    main(); /* call main */

    for (;;)
        (void)0; /* Infinite loop if main returns */
}

/* Stack pointer register */
extern void _estack(void);

typedef void (*const vector_table_t[16 + 91])(void);
/* 16 standard and 91 STM32 specific handlers in the vector table */
__attribute__((section(".vectors")))
vector_table_t tab = {[0] = _estack, [1] = _reset, [15] = SysTick_Handler};
