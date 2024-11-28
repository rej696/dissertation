#include "app/frame_buffer.h"

#include "rtos/thread.h"
#include "utils/cbuf.h"
#include "utils/dbc_assert.h"
#include "utils/debug.h"
#include "utils/status.h"
#include "utils/endian.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static struct {
    cbuf_t cbuf;
    bool ready;
    bool lock;
    status_t read_last_status;
    status_t write_last_status;
    uint32_t read_error_count;
    uint32_t write_error_count;
} self = {0};

static status_t frame_buffer_read_inner(cbuf_t *const cbuf)
{
    if (!self.ready) {
        return STATUS_OK;
    }

    /* FIXME replace with rtos aware queue/mutex */
    /* Mutex, if packet buffer is locked, delay and retry */
    while (self.lock) {
        rtos_delay(2);
    }
    self.lock = true;

    size_t size = cbuf_size(&self.cbuf);
    uint8_t tmp_buf[CBUF_SIZE] = {0};
    status_t status = cbuf_read(&self.cbuf, size, tmp_buf);

    if (status != STATUS_OK) {
        self.ready = false;
        cbuf_init(&self.cbuf);
        /* Release mutex lock */
        self.lock = false;
        return status;
    }
    /* Release mutex lock */
    self.lock = false;
    self.ready = false;

    /* Place contents of buffer into cbuf */
    status = cbuf_write(cbuf, size, tmp_buf);
    if (status != STATUS_OK) {
        DEBUG("Failed to write tmp buf to spacepacket cbuf", status);
        cbuf_init(cbuf);
    }

    return status;
}

static status_t frame_buffer_write_inner(size_t const size, uint8_t const buf[size])
{
    status_t status = STATUS_OK;
    /* TODO push the buffer that has been read into the queue */
    /* FIXME replace with rtos aware queue/mutex */
    /* Mutex, if frame buffer is locked, delay and retry */
    while (self.lock) {
        rtos_delay(2);
    }
    self.lock = true;
    status = cbuf_write(&self.cbuf, size, buf);
    if (status != STATUS_OK) {
        self.ready = false;
        /* Release frame buffer mutex */
        self.lock = false;
        return status;
    }
    /* Mark frame buffer as ready */
    self.ready = true;
    /* Release frame buffer mutex */
    self.lock = false;
    return status;
}

void frame_buffer_init(void)
{
    memset(&self, 0, sizeof(self));
    cbuf_init(&self.cbuf);
}

status_t frame_buffer_read(cbuf_t *const cbuf)
{
    status_t status = frame_buffer_read_inner(cbuf);
    if (status != STATUS_OK) {
        self.read_error_count++;
    }
    self.read_last_status = status;
    return status;
}

status_t frame_buffer_write(size_t const size, uint8_t const buf[size])
{
    status_t status = frame_buffer_write_inner(size, buf);
    if (status != STATUS_OK) {
        self.write_error_count++;
    }
    self.write_last_status = status;
    return status;
}

/* Telemetry Handlers */

status_t frame_buffer_read_error_count(size_t *const size, uint8_t *const output)
{
    DBC_REQUIRE(size != NULL);
    DBC_REQUIRE(output != NULL);

    *size = 4;
    endian_u32_to_network(self.read_error_count, output);
    return STATUS_OK;
}

status_t frame_buffer_read_last_status(size_t *const size, uint8_t *const output)
{
    DBC_REQUIRE(size != NULL);
    DBC_REQUIRE(output != NULL);

    *size = 1;
    output[0] = (uint8_t)self.read_last_status;
    return STATUS_OK;
}

status_t frame_buffer_write_error_count(size_t *const size, uint8_t *const output)
{
    DBC_REQUIRE(size != NULL);
    DBC_REQUIRE(output != NULL);

    *size = 4;
    endian_u32_to_network(self.write_error_count, output);
    return STATUS_OK;
}

status_t frame_buffer_write_last_status(size_t *const size, uint8_t *const output)
{
    DBC_REQUIRE(size != NULL);
    DBC_REQUIRE(output != NULL);

    *size = 1;
    output[0] = (uint8_t)self.read_last_status;
    return STATUS_OK;
}
