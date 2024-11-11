#include "app/action.h"
#include "app/parameter.h"
#include "app/spacepacket.h"
#include "app/telemetry.h"
#include "hal/gpio.h"
#include "hal/pinutils.h"
#include "hal/stm32f4_blackpill.h"
#include "hal/systick.h"
#include "hal/uart.h"
#include "rtos/thread.h"
#include "utils/cbuf.h"
#include "utils/debug.h"
#include "utils/status.h"
#include "utils/endian.h"

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
        packet_buffer_ready = false;

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
    uint8_t buf[CBUF_SIZE] = {0};
    cbuf_t *cbuf = uart_cbuf_get(UART1);
    cbuf_init(cbuf);

    for (;;) {
        size_t size = cbuf_size(cbuf);
        if (size > 0) {
            disable_irq();
            status_t status = cbuf_read(cbuf, size, &buf[0]);
            enable_irq();
            if (status != STATUS_OK) {
                /* TOOD handle this error */
                DEBUG("Failed to read from uart buffer", status);
                continue;
            }
#if 0 /* Debug uart read */
            debug_hex(size, &buf[0]);
#endif
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
        rtos_delay(100);
    }
}

static status_t print_hello(void)
{
    debug_str("Good news, Everyone!");
    return STATUS_OK;
}

uint8_t u8_param = 0;

static status_t get_u8_param(size_t *const size, uint8_t *const output)
{
    *size = 1;
    *output = u8_param;
    return STATUS_OK;
}

static status_t set_u8_param(size_t size, uint8_t const *const input)
{
    if (size != 1) {
        DEBUG("Invalid arguments for test_param", PARAMETER_STATUS_INVALID_PAYLOAD_SIZE);
        return PARAMETER_STATUS_INVALID_PAYLOAD_SIZE;
    }
    u8_param = *input;
    return STATUS_OK;
}

static status_t print_u8_param(void)
{
    debug_int(u8_param);
    return STATUS_OK;
}

uint32_t u32_param = 0;

static status_t get_u32_param(size_t *const size, uint8_t *const output)
{
    *size = 1;
    endian_u32_to_network(u32_param, output);
    return STATUS_OK;
}

static status_t set_u32_param(size_t size, uint8_t const *const input)
{
    if (size != 4) {
        DEBUG("Invalid arguments for test_param", PARAMETER_STATUS_INVALID_PAYLOAD_SIZE);
        return PARAMETER_STATUS_INVALID_PAYLOAD_SIZE;
    }
    endian_u32_from_network(input, &u32_param);
    return STATUS_OK;
}

static status_t print_u32_param(void)
{
    debug_int(u32_param);
    return STATUS_OK;
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

    /* Register actions/parameters/tlms */
    action_register(0, print_hello);

    action_register(1, print_u8_param);
    action_register(2, print_u32_param);
    parameter_register(1, (parameter_handler_t) {.set = set_u8_param, .get = get_u8_param});
    parameter_register(2, (parameter_handler_t) {.set = set_u32_param, .get = get_u32_param});


    rtos_run();

    return 0;
}
