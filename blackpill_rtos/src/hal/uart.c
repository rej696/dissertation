#include "hal/uart.h"

#include "hal/gpio.h"
#include "hal/pinutils.h"
#include "hal/stm32f4_blackpill.h"
#include "hal/systick.h"
#include "utils/cbuf.h"
#include "utils/dbc_assert.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static uart_t *const uart_map[3] = {
    [UART1] = ((uart_t *)0x40011000), /* USART 1 */
    [UART2] = ((uart_t *)0x40004400), /* USART 2 */
    [UART6] = ((uart_t *)0x40011400)  /* USART 6 */
};

static IRQn_Type const uart_irq_map[3] = {
    [UART1] = USART1_IRQn,
    [UART2] = USART2_IRQn,
    [UART6] = USART6_IRQn,
};

static cbuf_t uart_buf_map[3] = {
    [UART1] = {0},
    [UART2] = {0},
    [UART6] = {0},
};

/* USART IRQ Handlers */

/* Static inline cbuf function */
static inline void cbuf_isr_put(cbuf_t *const self, uint8_t const value)
{
    if (((self->write + 1) % CBUF_SIZE) != self->read) {
        self->buf[self->write] = value;
        self->write = (self->write + 1) % CBUF_SIZE;
    }
}

static inline void uart_read_isr(uart_t *const uart, cbuf_t *const cbuf)
{
    /* receive register not empty (bit 5 is SR->RXNE) */
    if (uart->SR & BIT(5)) {
        /* Copy byte into cbuf */
        cbuf_isr_put(cbuf, (uart->DR & 0xFF));
    }
}

void USART1_IRQHandler(void)
{
    static cbuf_t *const cbuf = &uart_buf_map[UART1];
    static uart_t *const uart = uart_map[UART1];
    uart_read_isr(uart, cbuf);
}

void USART2_IRQHandler(void)
{
    static cbuf_t *const cbuf = &uart_buf_map[UART2];
    static uart_t *const uart = uart_map[UART2];
    uart_read_isr(uart, cbuf);
}

void USART6_IRQHandler(void)
{
    static cbuf_t *const cbuf = &uart_buf_map[UART6];
    static uart_t *const uart = uart_map[UART6];
    uart_read_isr(uart, cbuf);
}

void uart_init(uart_id_t const uart_id, uint32_t const baud)
{
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
#if 0 /* Non-interrupt driven setup */
    /* 13 = uart enable, 3 = transmit enable, 2 = receive enable */
    uart_map[uart_id]->CR1 |= BIT(13) | BIT(3) | BIT(2);
#endif
    /* uart enable, receive enable, transmit enable, receive interrupt enable (RXNEIE) */
    uart_map[uart_id]->CR1 |= BIT(13) | BIT(3) | BIT(2) | BIT(5);

    /* Setup UART NVIC */
    NVIC_SetPriorityGrouping(0);
    uint32_t uart_pri_encoding = NVIC_EncodePriority(0, 1, 0);
    NVIC_SetPriority(uart_irq_map[uart_id], uart_pri_encoding);
    NVIC_EnableIRQ(uart_irq_map[uart_id]);
}

bool uart_read_ready(uart_id_t const uart_id)
{
    return uart_map[uart_id]->SR & BIT(5); /* Data is ready if RXNE bit is set */
}

uint8_t uart_read_byte(uart_id_t const uart_id) { return (uint8_t)(uart_map[uart_id]->DR & 0xFF); }

static inline void spin(volatile uint32_t count)
{
    while (count--) {
        (void)0;
    }
}

void uart_write_byte(uart_id_t const uart_id, uint8_t const byte)
{
    uart_map[uart_id]->DR = byte;
    while ((uart_map[uart_id]->SR & BIT(7)) == 0) {
        spin(1);
    }
}

void uart_write_hex_byte(uart_id_t const uart_id, uint8_t const byte)
{
    static char const *const hex_lookup = "0123456789ABCDEF";

    uint8_t nibble = (byte >> 4) & 0x0F;
    DBC_ASSERT(nibble < 16);
    uart_write_byte(uart_id, hex_lookup[nibble]);
    nibble = byte & 0x0F;
    DBC_ASSERT(nibble < 16);
    uart_write_byte(uart_id, hex_lookup[nibble]);
}

void uart_write_str(uart_id_t const uart_id, char const *const str)
{
    DBC_REQUIRE(str != NULL);

    for (uint32_t i = 0; str[i] != 0; ++i) {
        uart_write_byte(uart_id, (uint8_t)str[i]);
    }
}

void uart_write_buf(uart_id_t const uart_id, uint32_t const size, uint8_t const buf[size])
{
    DBC_REQUIRE(size > 0U);
    DBC_REQUIRE(buf != NULL);

    for (uint32_t i = 0; i < size; ++i) {
        uart_write_byte(uart_id, buf[i]);
    }
}

void uart_write_hex_buf(uart_id_t const uart_id, uint32_t const size, uint8_t const buf[size])
{
    DBC_REQUIRE(size > 0U);
    DBC_REQUIRE(buf != NULL);

    for (uint32_t i = 0; i < size; ++i) {
        uart_write_hex_byte(uart_id, buf[i]);
    }
    uart_write_byte(uart_id, '\r');
    uart_write_byte(uart_id, '\n');
}
