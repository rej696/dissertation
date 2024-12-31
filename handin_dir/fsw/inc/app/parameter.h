#ifndef APP_PARAMETER_H_
#define APP_PARAMETER_H_

#include "utils/status.h"

#include <stddef.h>
#include <stdint.h>

typedef status_t (*set_parameter_handler_t)(size_t, uint8_t const *const);
typedef status_t (*get_parameter_handler_t)(size_t *const, uint8_t *const);
typedef struct {
    set_parameter_handler_t set;
    get_parameter_handler_t get;
} parameter_handler_t;

status_t parameter_register(uint8_t id, parameter_handler_t handler);
status_t get_parameter_handler(
    size_t input_size,
    uint8_t const *const input_buffer,
    size_t *const output_size,
    uint8_t *const output_buffer);
status_t set_parameter_handler(
    size_t input_size,
    uint8_t const *const input_buffer,
    size_t *const output_size,
    uint8_t *const output_buffer);

#endif /* APP_PARAMETER_H_ */
