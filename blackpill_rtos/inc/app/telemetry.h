#ifndef APP_TELEMETRY_H_
#define APP_TELEMETRY_H_

#include "utils/status.h"

#include <stddef.h>
#include <stdint.h>

typedef status_t telemetry_handler_t(size_t *const, uint8_t *const);
status_t telemetry_register(uint8_t id, telemetry_handler_t handler);
status_t telemetry_handler(
    size_t input_size,
    uint8_t const *const input_buffer,
    size_t *const output_size,
    uint8_t *const output_buffer);

#endif /* APP_TELEMETRY_H_ */
