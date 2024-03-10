#include <stdint.h>
#include <stdbool.h>
#include "pinutils.h"
#include "gpio.h"
#include "uart.h"
#include "systick.h"


int main(void)
{
    uint16_t led = PIN('C', 13);
    gpio_set_mode(led, GPIO_MODE_OUTPUT);
    systick_init(CLOCK_FREQ / 1000); /* tick every ms */
    uint32_t timer = 0;
    uint32_t period = 500; /* Toggle LEDs every 500 ms */
    uart_init(UART1, 9600);

    while (1) {
        if (systick_timer_expired(&timer, period, systick_get_ticks())) {
            static bool on = true;
            gpio_write(led, on);
            on = !on;
            uart_write_str(UART1, on ? "tick\r\n" : "tock\r\n");
        }

        /* Modify speed of the timer based on uart1 input */
        if (uart_read_ready(UART1)) {
            uint8_t byte = uart_read_byte(UART1);
            uart_write_byte(UART1, byte);
            if (byte == '+') {
                period >>= 1;
            } else if (byte == '-') {
                period <<= 1;
            }
        }
    }

    return 0;
}

