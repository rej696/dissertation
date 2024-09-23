#include "hal/systick.h"

#include <stdint.h>

/* forward declare main function */
extern int main(void);

/* Startup code */
__attribute__((noreturn)) void _reset(void)
{
    /* declare linkerscript symbols */
    extern uint32_t __bss_start__, __bss_end__;   /* Start/end of .bss section */
    extern uint32_t __data_start__, __data_end__; /* Start/end of .data section in flash */
    extern uint32_t _sidata;        /* Start of .data section in sram */

    /* set .bss to zero */
    for (uint32_t *dst = &__bss_start__; dst < &__bss_end__; ++dst) {
        *dst = 0U;
    }

    for (uint32_t *dst = &__data_start__, *src = &_sidata; dst < &__data_end__; ++dst, ++src) {
        *dst = *src;
    }

    main(); /* call main */

    for (;;)
        (void)0; /* Infinite loop if main returns */
}

void _dummy(void)
{
    (void)0;
}

/* Stack pointer register */
extern void _estack(void);

typedef void (*const vector_table_t[16 + 91])(void);
/* 16 standard and 91 STM32 specific handlers in the vector table */
__attribute__((section(".vectors")))
vector_table_t tab = {
    [0] = _estack,
    [1] = _reset,
    [2] = _dummy,
    [3] = _dummy,
    [4] = _dummy,
    [5] = _dummy,
    [6] = _dummy,
    [7] = _dummy,
    [8] = _dummy,
    [9] = _dummy,
    [10] = _dummy,
    [11] = _dummy,
    [12] = _dummy,
    [13] = _dummy,
    [14] = _dummy,
    [15] = SysTick_Handler,
    [16] = _dummy,
    [17] = _dummy,
    [18] = _dummy,
    [19] = _dummy,
    [20] = _dummy,
    [21] = _dummy,
    [22] = _dummy,
    [23] = _dummy,
    [24] = _dummy,
    [25] = _dummy,
    [26] = _dummy,
    [27] = _dummy,
    [28] = _dummy,
    [29] = _dummy,
    [30] = _dummy,
    [31] = _dummy,
    [32] = _dummy,
    [33] = _dummy,
    [34] = _dummy,
    [35] = _dummy,
    [36] = _dummy,
    [37] = _dummy,
    [38] = _dummy,
    [39] = _dummy,
    [40] = _dummy,
    [41] = _dummy,
    [42] = _dummy,
    [43] = _dummy,
    [44] = _dummy,
    [45] = _dummy,
    [46] = _dummy,
    [47] = _dummy,
    [48] = _dummy,
    [49] = _dummy,
    [50] = _dummy,
    [51] = _dummy,
    [52] = _dummy,
    [53] = _dummy,
    [54] = _dummy,
    [55] = _dummy,
    [56] = _dummy,
    [57] = _dummy,
    [58] = _dummy,
    [59] = _dummy,
    [60] = _dummy,
    [61] = _dummy,
    [62] = _dummy,
    [63] = _dummy,
    [64] = _dummy,
    [65] = _dummy,
    [66] = _dummy,
    [67] = _dummy,
    [68] = _dummy,
    [69] = _dummy,
    [70] = _dummy,
    [71] = _dummy,
    [72] = _dummy,
    [73] = _dummy,
    [74] = _dummy,
    [75] = _dummy,
    [76] = _dummy,
    [77] = _dummy,
    [78] = _dummy,
    [79] = _dummy,
    [80] = _dummy,
    [81] = _dummy,
    [82] = _dummy,
    [83] = _dummy,
    [84] = _dummy,
    [85] = _dummy,
    [86] = _dummy,
    [87] = _dummy,
    [88] = _dummy,
    [89] = _dummy,
    [90] = _dummy,
    [91] = _dummy,
    [92] = _dummy,
    [93] = _dummy,
    [94] = _dummy,
    [95] = _dummy,
    [96] = _dummy,
    [97] = _dummy,
    [98] = _dummy,
    [99] = _dummy,
    [100] = _dummy,
    [101] = _dummy,
    [102] = _dummy,
    [103] = _dummy,
    [104] = _dummy,
    [105] = _dummy,
};
