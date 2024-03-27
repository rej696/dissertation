#include "uart.h"
#include "gpio.h"
#include "pinutils.h"
#include "systick.h"
#include "utils/dbc_assert.h"
#include <stdint.h>
#include <stdbool.h>

uart_t *uart_map[3] = {
    [UART1] = ((uart_t *) 0x40011000), /* USART 1 */
    [UART2] = ((uart_t *) 0x40004400), /* USART 2 */
    [UART6] = ((uart_t *) 0x40011400) /* USART 6 */
};

void uart_init(uart_id_t const uart_id, uint32_t const baud) {
    DBC_REQUIRE((uart_id >= UART1) && (uart_id <= UART6));
    DBC_REQUIRE(baud != 0);
    uint8_t af = 0; /* Alternate Function */
    uint16_t rx = 0;
    uint16_t tx = 0;
    switch (uart_id) {
        case UART1: {
            RCC->APB2ENR |= BIT(4);
            tx = PIN('A', 9);
            rx = PIN('A', 10);
            af = 7;
            break;
        }
        case UART2: {
            RCC->APB1ENR |= BIT(17);
            tx = PIN('A', 2);
            rx = PIN('A', 3);
            af = 7;
            break;
        }
        case UART6: {
            RCC->APB2ENR |= BIT(5);
            tx = PIN('A', 11);
            rx = PIN('A', 12);
            af = 8;
            break;
        }
    }

    gpio_set_mode(tx, GPIO_MODE_AF);
    gpio_set_af(tx, af);
    gpio_set_mode(rx, GPIO_MODE_AF);
    gpio_set_af(rx, af);
    uart_map[uart_id]->CR1 = 0;
    uart_map[uart_id]->BRR = CLOCK_FREQ / baud;
    /* 13 = uart enable, 3 = transmit enable, 2 = receive enable */
    uart_map[uart_id]->CR1 |= BIT(13) | BIT(3) | BIT(2);
}

bool uart_read_ready(uart_id_t const uart_id) {
    return uart_map[uart_id]->SR & BIT(5); /* Data is ready if RXNE bit is set */
}

uint8_t uart_read_byte(uart_id_t const uart_id) {
    return (uint8_t)(uart_map[uart_id]->DR & 0xFF);
}

static inline void spin(volatile uint32_t count) {
    while (count--) { (void) 0; }
}

void uart_write_byte(uart_id_t const uart_id, uint8_t const byte) {
    uart_map[uart_id]->DR = byte;
    while ((uart_map[uart_id]->SR & BIT(7)) == 0) { spin(1); }
}

void uart_write_str(uart_id_t const uart_id, char const *const str) {
    for (uint32_t i = 0; str[i] != 0; ++i) {
        uart_write_byte(uart_id, (uint8_t)str[i]);
    }
}

void uart_write_buf(uart_id_t const uart_id, uint32_t const size, uint8_t const buf[size]) {
    for (uint32_t i = 0; i < size; ++i) {
        uart_write_byte(uart_id, buf[i]);
    }
}
