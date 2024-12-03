#include "app/action.h"
#include "app/frame_buffer.h"
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
#include "utils/utils.h"

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
        rtos_delay(1);
    }
}

void packet_thread_handler(void)
{
    bool packet_complete = false;
    size_t packet_size = 0;
    uint8_t packet_buffer[CBUF_SIZE] = {0};
    cbuf_t kiss_frame_cbuf = {0};
    cbuf_init(&kiss_frame_cbuf);

    /* recieve a buffer of data in a queue and process it */
    for (;;) {
        status_t status = frame_buffer_read(&kiss_frame_cbuf);
        if (status != STATUS_OK) {
            DEBUG("Error reading frame buffer", status);
        }

        /* data extracted from frame buffer is available to be deframed */
        if (cbuf_size(&kiss_frame_cbuf) > 0) {
            packet_complete = kiss_frame_unpack(&kiss_frame_cbuf, &packet_size, packet_buffer);
        }

        /* No spacepackets available to process */
        if ((packet_size <= 0) || (!packet_complete)) {
            /* frame not finished, save buffer state, delay (to context switch to other task)
             * and continue */
            rtos_delay(2);
            continue;
        }
#if 0
        debug_hex("recv packet", packet_size, packet_buffer);
#endif

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
        /* Clear packet buffer once processed */
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
            if (status != STATUS_OK) {
                DEBUG("Failed to read from uart buffer", status);
                continue;
            }
            status = frame_buffer_write(size, buf);
            if (status != STATUS_OK) {
                DEBUG("Failed to write to frame buffer", status);
            }
        }
        rtos_delay(1);
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
        DEBUG("Invalid arguments for set_u8_param", PARAMETER_STATUS_INVALID_PAYLOAD_SIZE);
        return PARAMETER_STATUS_INVALID_PAYLOAD_SIZE;
    }
    u8_param = *input;
    return STATUS_OK;
}

/* Test Actions/Parameters/Telemetries */

static status_t print_u8_param(void)
{
    DEBUG_INT("Printing u8 param:", u8_param);
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
        DEBUG("Invalid arguments for set_u32_param", PARAMETER_STATUS_INVALID_PAYLOAD_SIZE);
        return PARAMETER_STATUS_INVALID_PAYLOAD_SIZE;
    }
    endian_u32_from_network(input, &u32_param);
    return STATUS_OK;
}

static status_t print_u32_param(void)
{
    DEBUG_INT("Printing u32 param:", u32_param);
    return STATUS_OK;
}

static action_handler_t action_table[] = {
    print_hello,
    print_u8_param,
    print_u32_param,
};

static parameter_handler_t param_table[] = {
    {.set = set_u8_param, .get = get_u8_param},
    {.set = set_u32_param, .get = get_u32_param},
};

static telemetry_handler_t tlm_table[] = {
    spacepacket_out_of_seq_count,
    spacepacket_csum_error_count,
    spacepacket_last_seq_count,
    frame_buffer_read_error_count,
    frame_buffer_write_error_count,
    frame_buffer_read_last_status,
    frame_buffer_write_last_status,
};

int main(void)
{
    rtos_init(idle_thread_stack, sizeof(idle_thread_stack));
    uart_init(UART1, 9600);
    debug_init(UART2, 9600);
    cbuf_init(uart_cbuf_get(UART1));  // init uart1 cbuf
    frame_buffer_init();              // init frame buffer
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
    for (uint8_t i = 0; i < ARRAY_LEN(action_table); ++i) {
        action_register(i, action_table[i]);
    }
    for (uint8_t i = 0; i < ARRAY_LEN(param_table); ++i) {
        parameter_register(i, param_table[i]);
    }
    for (uint8_t i = 0; i < ARRAY_LEN(tlm_table); ++i) {
        telemetry_register(i, tlm_table[i]);
    }

    rtos_run();

    return 0;
}
