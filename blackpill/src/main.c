#include "hal/gpio.h"
#include "hal/pinutils.h"
#include "hal/systick.h"
#include "hal/uart.h"

#include <stdbool.h>
#include <stddef.h>

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
    }

    return 0;
}
