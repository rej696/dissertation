#include "utils/cbuf.h"

#include "utils/status.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>


void cbuf_init(cbuf_t *const self)
{
    self->write = 0;
    self->read = 0;
    /* memset(self->buf, 0U, CBUF_SIZE); */
}

status_t cbuf_put(cbuf_t *const self, uint8_t const value)
{
    if (((self->write + 1) % CBUF_SIZE) == self->read) {
        return CBUF_STATUS_CBUF_FULL;
    }
    self->buf[self->write] = value;
    self->write = (self->write + 1) % CBUF_SIZE;
    return STATUS_OK;
}

status_t cbuf_get(cbuf_t *const self, uint8_t *const value)
{
    if (self->write == self->read) {
        return CBUF_STATUS_CBUF_EMPTY;
    }
    *value = self->buf[self->read];
    self->read = (self->read + 1) % CBUF_SIZE;
    return STATUS_OK;
}

size_t cbuf_size(cbuf_t const *const self)
{
    if (self->read <= self->write) {
        return self->write - self->read;
    }
    return (CBUF_SIZE - self->read) + self->write;
}

status_t cbuf_read(cbuf_t *const self, size_t const size, uint8_t dest[size])
{
    if (size > cbuf_size(self)) {
        return CBUF_STATUS_BUFFER_OVERFLOW;
    }

    if (self->read < self->write) {
        memcpy(&dest[0], &self->buf[self->read], size);
        self->read += size;
    } else {
        size_t temp_size = CBUF_SIZE - self->read;
        memcpy(&dest[0], &self->buf[self->read], temp_size);
        memcpy(&dest[temp_size], &self->buf[0], size - temp_size);
        self->read = size - temp_size;
    }

    return STATUS_OK;
}

status_t cbuf_write(cbuf_t *const self, size_t const size, uint8_t const dest[size])
{
    if (size > (CBUF_SIZE - cbuf_size(self))) {
        return CBUF_STATUS_BUFFER_OVERFLOW;
    }

    if (self->write + size < CBUF_SIZE) {
        memcpy(&self->buf[self->write], &dest[0], size);
        self->write += size;
    } else {
        size_t temp_size = CBUF_SIZE - self->write;
        memcpy(&self->buf[self->write], &dest[0], temp_size);
        memcpy(&self->buf[0], &dest[temp_size], size - temp_size);
        self->write = size - temp_size;
    }

    return STATUS_OK;
}
