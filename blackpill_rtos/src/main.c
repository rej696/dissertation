#include "app/action.h"
#include "app/kiss_frame.h"
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
#include "utils/dbc_assert.h"
#include "utils/debug.h"
#include "utils/endian.h"
#include "utils/status.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * RTOS Threads
 * - Idle Thread
 * - Blink LED
 * - Read from UART
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
            debug_str(on ? "tick" : "tock");
            on = !on;
        }
    }
}

/* FIXME replace with rtos aware queue */
cbuf_t frame_buffer = {0};
bool frame_buffer_ready = false;
bool frame_buffer_lock = false;

status_t frame_buffer_read(cbuf_t *const cbuf)
{
    if (!frame_buffer_ready) {
        return STATUS_OK;
    }

    /* FIXME replace with rtos aware queue/mutex */
    /* Mutex, if packet buffer is locked, delay and retry */
    while (frame_buffer_lock) {
        rtos_delay(2);
    }
    frame_buffer_lock = true;

    size_t size = cbuf_size(&frame_buffer);
    uint8_t tmp_buf[256] = {0};
    status_t status = cbuf_read(&frame_buffer, size, tmp_buf);

    if (status != STATUS_OK) {
        frame_buffer_ready = false;
        cbuf_init(&frame_buffer);
        /* Release mutex lock */
        frame_buffer_lock = false;
        return status;
    }
    /* Release mutex lock */
    frame_buffer_lock = false;
    frame_buffer_ready = false;

    /* Place contents of buffer into cbuf */
    status = cbuf_write(cbuf, size, tmp_buf);
    if (status != STATUS_OK) {
        DEBUG("Failed to write tmp buf to spacepacket cbuf", status);
        cbuf_init(cbuf);
    }
    return status;
}

void packet_thread_handler(void)
{
    size_t packet_size = 0;
    uint8_t packet_buffer[256] = {0};
    cbuf_t kiss_frame_cbuf = {0};
    cbuf_init(&kiss_frame_cbuf);

    /* recieve a buffer of data in a queue and process it */
    for (;;) {
        status_t status = frame_buffer_read(&kiss_frame_cbuf);
        if (status != STATUS_OK) {
            /* FIXME Handle Error? clear buffers? */
            DEBUG("Error reading frame buffer", status);
        }

        bool packet_complete = kiss_frame_unpack(&kiss_frame_cbuf, &packet_size, packet_buffer);

        if (!packet_complete) {
            /* frame not finished, save buffer state, delay (to context switch to other task)
             * and continue */
            rtos_delay(2);
            continue;
        }

        /* parse buffer as a spacepacket */
        size_t response_size = 0;
        uint8_t response_buffer[SPACEPACKET_HDR_SIZE + SPACEPACKET_DATA_MAX_SIZE] = {0};
        /* Process buffer */
        status = spacepacket_process(packet_size, packet_buffer, &response_size, response_buffer);
        if (status == STATUS_OK) {
            size_t output_frame_size = 0;
            uint8_t output_frame_buffer[(SPACEPACKET_HDR_SIZE + SPACEPACKET_DATA_MAX_SIZE) * 2] = {
                0};
            kiss_frame_pack(
                response_size,
                response_buffer,
                &output_frame_size,
                output_frame_buffer);
            uart_write_buf(UART1, output_frame_size, output_frame_buffer);
        } else {
            DEBUG("Failed to process spacepacket", status);
        }
        /* FIXME clear packet buffer? */
        packet_size = 0;
    }
}

void uart_handler(void)
{
    uint8_t buf[CBUF_SIZE] = {0};
    cbuf_t *const cbuf = uart_cbuf_get(UART1);

    for (;;) {
        size_t size = cbuf_size(cbuf);
        if (size > 0) {
            disable_irq();
            status_t status = cbuf_read(cbuf, size, &buf[0]);
            enable_irq();
#if 0
            DEBUG("Read uart buffer with status", status);
#endif
            if (status != STATUS_OK) {
                /* TODO handle this error */
                DEBUG("Failed to read from uart buffer", status);
                continue;
            }
#if 0 /* Debug uart read */
            debug_hex(size, &buf[0]);
#endif
            /* TODO push the buffer that has been read into the queue */
            /* FIXME replace with rtos aware queue/mutex */
            /* Mutex, if frame buffer is locked, delay and retry */
            while (frame_buffer_lock) {
#if 0
                debug_str("waiting for packet buffer mutex lock");
#endif
                rtos_delay(2);
            }
#if 0
            debug_str("packet buffer mutex locked");
#endif
            frame_buffer_lock = true;
            status = cbuf_write(&frame_buffer, size, buf);
            if (status != STATUS_OK) {
                DEBUG("Failed to write uart data to packet buffer", status);
                frame_buffer_ready = false;
                /* Release packet buffer mutex */
                frame_buffer_lock = false;
                continue;
            }

            /* Mark frame buffer as ready */
            frame_buffer_ready = true;
            /* Release frame buffer mutex */
            frame_buffer_lock = false;
#if 0
            debug_str("retrieved data from uart");
#endif
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
    debug_str("Printing u8 param:");
    debug_int(u8_param);
    return STATUS_OK;
}

uint32_t u32_param = 0;

static status_t get_u32_param(size_t *const size, uint8_t *const output)
{
    *size = 4;
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
    debug_str("Printing u32 param:");
    debug_int(u32_param);
    return STATUS_OK;
}

int main(void)
{
    rtos_init(idle_thread_stack, sizeof(idle_thread_stack));
    uart_init(UART1, 9600);
    debug_init(UART2, 9600);
    cbuf_init(uart_cbuf_get(UART1));  // init uart1 cbuf
    cbuf_init(&frame_buffer);         // init frame buffer
    debug_str("boot");

    rtos_thread_create(&blinky_thread, &blinky_handler, blinky_stack, sizeof(blinky_stack));
    rtos_thread_create(&uart_thread, &uart_handler, uart_stack, sizeof(uart_stack));
    rtos_thread_create(
        &packet_thread,
        &packet_thread_handler,
        packet_thread_stack,
        sizeof(packet_thread_stack));

    debug_str("threads created");
#if 0
    debug_str("Blinky Thread Stack Created: (addr, size)");
    debug_int((uint32_t)blinky_stack);
    debug_int((uint32_t)(blinky_stack + BLINKY_STACK_SIZE));
    debug_str("UART Thread Stack Created: (addr, size)");
    debug_int((uint32_t)uart_stack);
    debug_int((uint32_t)(uart_stack + UART_STACK_SIZE));
    debug_str("Packet Thread Stack Created: (addr, size)");
    debug_int((uint32_t)packet_thread_stack);
    debug_int((uint32_t)(packet_thread_stack + PACKET_THREAD_STACK_SIZE));
#endif

    /* Register actions/parameters/tlms */
    action_register(0, print_hello);

    action_register(1, print_u8_param);
    action_register(2, print_u32_param);
    parameter_register(1, (parameter_handler_t) {.set = set_u8_param, .get = get_u8_param});
    parameter_register(2, (parameter_handler_t) {.set = set_u32_param, .get = get_u32_param});

    rtos_run();

    return 0;
}
