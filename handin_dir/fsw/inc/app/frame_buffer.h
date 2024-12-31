
#ifndef APP_FRAME_BUFFER_H_
#define APP_FRAME_BUFFER_H_

#include "utils/cbuf.h"
#include "utils/status.h"

#include <stddef.h>
#include <stdint.h>

void frame_buffer_init(void);

status_t frame_buffer_read(cbuf_t *const cbuf);

status_t frame_buffer_write(size_t const size, uint8_t const buf[size]);

/* Telemetry Handlers */
status_t frame_buffer_read_error_count(size_t *const size, uint8_t *const output);
status_t frame_buffer_read_last_status(size_t *const size, uint8_t *const output);
status_t frame_buffer_write_error_count(size_t *const size, uint8_t *const output);
status_t frame_buffer_write_last_status(size_t *const size, uint8_t *const output);

#endif /* APP_FRAME_BUFFER_H_ */
