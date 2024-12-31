#include "utils/debug.h"

#include "hal/uart.h"
#include "utils/dbc_assert.h"
#include "utils/status.h"

#include <stddef.h>
#include <stdint.h>

static uart_id_t debug_uart_id = UART2;

void debug_init(uart_id_t const uart_id, uint32_t const baud)
{
    debug_uart_id = uart_id;
    uart_init(debug_uart_id, baud);
}

void debug_status(char const *const msg, status_t status)
{
    DBC_REQUIRE(msg != NULL);
    uart_write_str(debug_uart_id, msg);
    uart_write_str(debug_uart_id, " (0x");
#ifdef STATUS_ENUM_GREATER_THAN_UINT8 /* Code for bigger status values */
    for (int i = 3; i < 0; --i) {
        uint8_t byte = (((uint32_t)status) >> (i * 8)) & 0xFF;
        uart_write_hex_byte(debug_uart_id, byte);
    }
#else
    DBC_REQUIRE(STATUS_MAX <= 0xFF);
    uart_write_hex_byte(debug_uart_id, (uint8_t)(status & 0xFF));
#endif
    uart_write_str(debug_uart_id, ")\r\n");
}

void debug_str(char const *const msg)
{
    DBC_REQUIRE(msg != NULL);
    uart_write_str(debug_uart_id, msg);
    uart_write_str(debug_uart_id, "\r\n");
}

void debug_int(char const *const msg, uint32_t value)
{
    DBC_REQUIRE(msg != NULL);
    uart_write_str(debug_uart_id, msg);
    uart_write_str(debug_uart_id, " (0x");
    for (int i = 3; i >= 0; --i) {
        uint8_t byte = (((uint32_t)value) >> (i * 8)) & 0xFF;
        uart_write_hex_byte(debug_uart_id, byte);
    }
    uart_write_str(debug_uart_id, ")\r\n");
}

void debug_hex(char const *const msg, uint32_t const size, uint8_t const buf[size])
{
    DBC_REQUIRE(size > 0U);
    DBC_REQUIRE(buf != NULL);
    DBC_REQUIRE(msg != NULL);
    uart_write_str(debug_uart_id, msg);
    uart_write_str(debug_uart_id, ":\r\n");

    for (uint32_t i = 0; i < size; ++i) {
        uart_write_hex_byte(debug_uart_id, buf[i]);
        /* print a newline every 16th byte, or on the last byte */
        if (((i > 0) && ((i % 16) == 0)) || (i == (size - 1))) {
            uart_write_str(debug_uart_id, "\r\n");
        } else {
            uart_write_byte(debug_uart_id, ' ');
        }
    }
}
