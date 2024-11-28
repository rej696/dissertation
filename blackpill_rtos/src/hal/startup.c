#include <stdint.h>

#include "hal/stm32f4_blackpill.h"
#include "hal/uart.h"

/* forward declare main function */
extern int main(void);

/* Startup code */
__attribute__((noreturn)) void Reset_Handler(void)
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

void assert_failed(char const *file, int line) {
    /* TODO: handle a fault */
    (void)file;
    (void)line;
    uart_write_str(UART2, "Hardfault!!\r\n");
    /* *((uint32_t *)0x40004404) = 'd'; */
    NVIC_SystemReset();
}

__attribute__((naked)) void Default_Handler(void)
{
    uart_write_str(UART2, "default_handler\r\n");
    asm("nop");
}

__attribute__((naked)) void Reserved(void)
{
    asm("nop");
}

/* Fault Exception Handlers */
void NMI_Handler(void) __attribute__((weak));
void HardFault_Handler(void) __attribute__((weak));
void MemManage_Handler(void) __attribute__((weak));
void BusFault_Handler(void) __attribute__((weak));
void UsageFault_Handler(void) __attribute__((weak));

/* Non-Fault Exception Handlers */
void SVC_Handler(void) __attribute__((weak, alias("Default_Handler")));
void DebugMon_Handler(void) __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void) __attribute__((weak, alias("Default_Handler")));
void SysTick_Handler(void) __attribute__((weak, alias("Default_Handler")));

/* Device IRQ Handlers */
void USART1_IRQHandler(void) __attribute__((weak, alias("Default_Handler")));
void USART2_IRQHandler(void) __attribute__((weak, alias("Default_Handler")));
void USART6_IRQHandler(void) __attribute__((weak, alias("Default_Handler")));

/* end of stack pointer */
extern void __stack_end__(void);

typedef void (*const vector_table_t[16 + 91])(void);
/* 16 standard and 91 STM32 specific handlers in the vector table */
__attribute__((section(".vectors")))
vector_table_t tab = {
    [0] = __stack_end__,
    [1] = Reset_Handler,
    [2] = NMI_Handler,
    [3] = HardFault_Handler,
    [4] = MemManage_Handler,
    [5] = BusFault_Handler,
    [6] = UsageFault_Handler,
    [7] = Reserved,
    [8] = Reserved,
    [9] = Reserved,
    [10] = Reserved,
    [11] = SVC_Handler,
    [12] = DebugMon_Handler,
    [13] = Reserved,
    [14] = PendSV_Handler,
    [15] = SysTick_Handler,

    /* IRQ Handlers */
    [16] = Default_Handler,
    [17] = Default_Handler,
    [18] = Default_Handler,
    [19] = Default_Handler,
    [20] = Default_Handler,
    [21] = Default_Handler,
    [22] = Default_Handler,
    [23] = Default_Handler,
    [24] = Default_Handler,
    [25] = Default_Handler,
    [26] = Default_Handler,
    [27] = Default_Handler,
    [28] = Default_Handler,
    [29] = Default_Handler,
    [30] = Default_Handler,
    [31] = Default_Handler,
    [32] = Default_Handler,
    [33] = Default_Handler,
    [34] = Default_Handler,
    [35] = Default_Handler,
    [36] = Default_Handler,
    [37] = Default_Handler,
    [38] = Default_Handler,
    [39] = Default_Handler,
    [40] = Default_Handler,
    [41] = Default_Handler,
    [42] = Default_Handler,
    [43] = Default_Handler,
    [44] = Default_Handler,
    [45] = Default_Handler,
    [46] = Default_Handler,
    [47] = Default_Handler,
    [48] = Default_Handler,
    [49] = Default_Handler,
    [50] = Default_Handler,
    [51] = Default_Handler,
    [52] = Default_Handler,
    [53] = USART1_IRQHandler,
    [54] = USART2_IRQHandler,
    [55] = Default_Handler,
    [56] = Default_Handler,
    [57] = Default_Handler,
    [58] = Default_Handler,
    [59] = Default_Handler,
    [60] = Default_Handler,
    [61] = Default_Handler,
    [62] = Default_Handler,
    [63] = Default_Handler,
    [64] = Default_Handler,
    [65] = Default_Handler,
    [66] = Default_Handler,
    [67] = Default_Handler,
    [68] = Default_Handler,
    [69] = Default_Handler,
    [70] = Default_Handler,
    [71] = Default_Handler,
    [72] = Default_Handler,
    [73] = Default_Handler,
    [74] = Default_Handler,
    [75] = Default_Handler,
    [76] = Default_Handler,
    [77] = Default_Handler,
    [78] = Default_Handler,
    [79] = Default_Handler,
    [80] = Default_Handler,
    [81] = Default_Handler,
    [82] = Default_Handler,
    [83] = Default_Handler,
    [84] = Default_Handler,
    [85] = Default_Handler,
    [86] = Default_Handler,
    [87] = USART6_IRQHandler,
    [88] = Default_Handler,
    [89] = Default_Handler,
    [90] = Default_Handler,
    [91] = Default_Handler,
    [92] = Default_Handler,
    [93] = Default_Handler,
    [94] = Default_Handler,
    [95] = Default_Handler,
    [96] = Default_Handler,
    [97] = Default_Handler,
    [98] = Default_Handler,
    [99] = Default_Handler,
    [100] = Default_Handler,
    [101] = Default_Handler,
    [102] = Default_Handler,
    [103] = Default_Handler,
    [104] = Default_Handler,
    [105] = Default_Handler,
};

__attribute__((naked)) void HardFault_Handler(void)
{
    asm volatile (
        "    ldr r0,=str_hrd\n\t"
        "    mov r1,#1\n\t"
        "    b assert_failed\n\t"
        "str_hrd: .asciz \"HardFault\"\n\t"
    );
}
