#ifndef UART_H_
#define UART_H_

#include <stdbool.h>
#include <stdint.h>
#include "utils/cbuf.h"

typedef struct uart {
    volatile uint32_t SR;
    volatile uint32_t DR;
    volatile uint32_t BRR;
    volatile uint32_t CR1;
    volatile uint32_t CR2;
    volatile uint32_t CR3;
    volatile uint32_t GTPR;
} uart_t;

typedef enum uart_id {
    UART1 = 0,
    UART2 = 1,
    UART6 = 2
} uart_id_t;

/**
 * @brief Initialise the uart hardware with the given baudrate
 *
 * @pre baud shall not be 0
 *
 * @param uart_id[in] the id of the uart device
 * @param baud[in] the desired baudrate for the device
 */
void uart_init(uart_id_t const uart_id, uint32_t const baud);

/**
 * @brief Check if there is data available to be read from the uart
 *
 * @param uart_id[in] the id of the uart device
 * @return flag indicating if there is data to be read from the buffer
 */
bool uart_read_ready(uart_id_t const uart_id);
uint8_t uart_read_byte(uart_id_t const uart_id);
void uart_write_byte(uart_id_t const uart_id, uint8_t const byte);
void uart_write_hex_byte(uart_id_t const uart_id, uint8_t const byte);
void uart_write_str(uart_id_t const uart_id, char const *const str);
void uart_write_buf(uart_id_t const uart_id, uint32_t const size, uint8_t const buf[size]);
void uart_write_hex_buf(uart_id_t const uart_id, uint32_t const size, uint8_t const buf[size]);

/* Retrieve a pointer to the cbuf used to receive data in the isr */
cbuf_t *uart_cbuf_get(uart_id_t const uart_id);

#endif /* UART_H_ */
