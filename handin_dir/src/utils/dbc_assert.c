#include "utils/dbc_assert.h"

#include "hal/uart.h"

DBC_NORETURN void DBC_fault_handler(char const *const msg)
{
    /* Print File and line number */
    uart_write_str(UART2, msg);
    uart_write_str(UART2, ": DBC Failure!!\r\n");

    for (;;) {
        asm("nop");
    }
}
