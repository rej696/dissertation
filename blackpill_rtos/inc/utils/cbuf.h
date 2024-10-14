#ifndef CBUF_H_
#define CBUF_H_

#include "utils/status.h"

#include <stdint.h>
#include <stddef.h>

#define CBUF_SIZE (1024)

typedef struct cbuf {
    size_t write;
    size_t read;
    uint8_t buf[CBUF_SIZE];
} cbuf_t;

void cbuf_init(cbuf_t *const self);

size_t cbuf_size(cbuf_t const *const self);

status_t cbuf_get(cbuf_t *const self, uint8_t *const value);

status_t cbuf_put(cbuf_t *const self, uint8_t const value);

status_t cbuf_read(cbuf_t *const self, size_t const size, uint8_t dest[size]);

status_t cbuf_write(cbuf_t *const self, size_t const size, uint8_t const src[size]);

#endif /* CBUF_H_ */
