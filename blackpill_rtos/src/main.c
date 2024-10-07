#include "hal/gpio.h"
#include "hal/pinutils.h"
#include "hal/systick.h"
#include "hal/uart.h"

#include "rtos/thread.h"

#include <stdbool.h>
#include <stddef.h>


#define BLINKY_STACK_SIZE 40
#define UART_STACK_SIZE 40

/**
 * RTOS Threads
 * - Blink LED
 * - Print to UART
 */

/* Blinky Thread */
rtos_thread_t blinky_thread = {0};
uint32_t blinky_stack[BLINKY_STACK_SIZE] = {0};

void blinky_handler(void) {
    /* Setup Blinky */
    uint16_t led = PIN('C', 13);
    gpio_set_mode(led, GPIO_MODE_OUTPUT);
    uint32_t timer = 0;
    uint32_t period = 500; /* Toggle LEDs every 500 ms */

    /* Loop */
    for (;;) {
        if (systick_timer_expired(&timer, period, systick_get_ticks())) {
            static bool on = true;
            gpio_write(led, on);
            on = !on;
        }
    }
}


/* UART Thread */
rtos_thread_t uart_thread = {0};
uint32_t uart_stack[UART_STACK_SIZE] = {0};

void uart_handler(void) {
    uint32_t timer = 0;
    uint32_t period = 1500; /* Toggle UART every 1500 ms */

    for (;;) {
        if (systick_timer_expired(&timer, period, systick_get_ticks())) {
            static bool on = true;
            uart_write_str(UART1, on ? "tick\r\n" : "tock\r\n");
            on = !on;
        }

#if 0
        /* Modify speed of the timer based on uart1 input */
        if (uart_read_ready(UART1)) {
            uint8_t byte = uart_read_byte(UART1);
            char *string = "Invalid!\r\n";
            if (byte == '+') {
                period >>= 1;
                string = "+\r\n";
            } else if (byte == '-') {
                period <<= 1;
                string = "-\r\n";
            } else if (byte == '\0') {
                string[sizeof(string)] = '0';
            }
            uart_write_str(UART1, string);
        }
#endif
    }
}

int main(void)
{
    rtos_init();
    uart_init(UART1, 9600);
    uart_write_str(UART1, "boot\r\n");

    rtos_thread_create(&blinky_thread, &blinky_handler, blinky_stack, sizeof(blinky_stack));
    rtos_thread_create(&uart_thread, &uart_handler, uart_stack, sizeof(uart_stack));

    uart_write_str(UART1, "threads created\r\n");

    rtos_run();

    return 0;
}
