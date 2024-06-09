#include "utils/dbc_assert.h"

#include "hal/uart.h"

DBC_NORETURN void DBC_fault_handler(char const *module, int label)
{
    /* TODO setup printf to print line number */
    uart_write_str(UART2, "DBC_fault_handler raised in ");
    uart_write_str(UART2, module);
    (void)label;

    for (;;) {
        asm("nop");
    }
}
