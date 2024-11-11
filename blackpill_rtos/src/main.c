#include "app/spacepacket.h"
#include "hal/gpio.h"
#include "hal/pinutils.h"
#include "hal/systick.h"
#include "hal/uart.h"
#include "rtos/thread.h"
#include "utils/cbuf.h"
#include "utils/debug.h"
#include "utils/status.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * RTOS Threads
 * - Idle Thread
 * - Blink LED?
 * - Read/Write from UART
 * - Process Space Packets
 */

#define IDLE_THREAD_STACK_SIZE   (40)
#define BLINKY_STACK_SIZE        (512)
#define PACKET_THREAD_STACK_SIZE (2048)
#define UART_STACK_SIZE          (512)

/* Idle Thread */
uint32_t idle_thread_stack[IDLE_THREAD_STACK_SIZE] = {0};

/* Blinky Thread */
rtos_thread_t blinky_thread = {0};
uint32_t blinky_stack[BLINKY_STACK_SIZE] = {0};

/* Packet Thread */
rtos_thread_t packet_thread = {0};
uint32_t packet_thread_stack[PACKET_THREAD_STACK_SIZE] = {0};

/* UART Thread */
rtos_thread_t uart_thread = {0};
uint32_t uart_stack[UART_STACK_SIZE] = {0};

void blinky_handler(void)
{
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

/* FIXME replace with rtos aware queue */
cbuf_t packet_buffer = {0};
bool packet_buffer_ready = false;
bool packet_buffer_lock = false;

void packet_thread_handler(void)
{
    cbuf_init(&packet_buffer);

    /* recieve a buffer of data in a queue and process it */
    for (;;) {
        if (!packet_buffer_ready) {
            continue;
        }

        /* FIXME replace with rtos aware queue/mutex */
        /* Mutex, if packet buffer is locked, delay and retry */
        while (packet_buffer_lock) {
            rtos_delay(2);
        }
        packet_buffer_lock = true;

        size_t size = cbuf_size(&packet_buffer);
        uint8_t buffer[256] = {0};
        status_t status = cbuf_read(&packet_buffer, size, buffer);
        if (status != STATUS_OK) {
            DEBUG("Failed to read packet buffer", status);

            packet_buffer_ready = false;
            cbuf_init(&packet_buffer);
            /* Release mutex lock */
            packet_buffer_lock = false;
            continue;
        }
        /* Release mutex lock */
        packet_buffer_lock = false;

        /* Process buffer */
        status = spacepacket_process(size, buffer);
        if (status != STATUS_OK) {
            DEBUG("Failed to process spacepacket", status);
        }
        /* TODO handle response? */
    }
}

void uart_handler(void)
{
#ifdef TICKTOCK
    uint32_t timer = 0;
    uint32_t period = 1500; /* Toggle UART every 1500 ms */
#endif

#ifndef UART_READ
    uint8_t buf[CBUF_SIZE] = {0};
    cbuf_t cbuf = {0};
    cbuf_init(&cbuf);
#endif

    for (;;) {
#ifdef TICKTOCK
        if (systick_timer_expired(&timer, period, systick_get_ticks())) {
            static bool on = true;
            debug_str(on ? "tick" : "tock");
            on = !on;
        }
#endif

#ifndef UART_READ
        while (uart_read_ready(UART1)) {
            uint8_t byte = uart_read_byte(UART1);
            cbuf_put(&cbuf, byte);
            rtos_delay(1);
            /* continue; */
        }

        size_t size = cbuf_size(&cbuf);
        if (size > 0) {
            status_t status = cbuf_read(&cbuf, size, &buf[0]);
            if (status != STATUS_OK) {
                /* TOOD handle this error */
                DEBUG("Failed to read from uart buffer", status);
                continue;
            }
            debug_hex(size, &buf[0]);
            /* TODO push the buffer that has been read into the queue */
            /* FIXME replace with rtos aware queue/mutex */
            /* Mutex, if packet buffer is locked, delay and retry */
            while (packet_buffer_lock) {
                rtos_delay(2);
            }
            packet_buffer_lock = true;
            status = cbuf_write(&packet_buffer, size, buf);
            if (status != STATUS_OK) {
                DEBUG("Failed to write uart data to packet buffer", status);
                cbuf_init(&packet_buffer);
                packet_buffer_ready = false;
                /* Release packet buffer mutex */
                packet_buffer_lock = false;
                continue;
            }

            /* Mark packet buffer as ready */
            packet_buffer_ready = true;
            /* Release packet buffer mutex */
            packet_buffer_lock = false;
        }
#endif

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
    rtos_init(idle_thread_stack, sizeof(idle_thread_stack));
    uart_init(UART1, 9600);
    debug_init(UART2, 9600);
    debug_str("boot");

    rtos_thread_create(&blinky_thread, &blinky_handler, blinky_stack, sizeof(blinky_stack));
    rtos_thread_create(&uart_thread, &uart_handler, uart_stack, sizeof(uart_stack));
    rtos_thread_create(
        &packet_thread,
        &packet_thread_handler,
        packet_thread_stack,
        sizeof(packet_thread_stack));

    debug_str("threads created");

    rtos_run();

    return 0;
}
