#ifndef APP_ACTION_H_
#define APP_ACTION_H_

#include "utils/status.h"

#include <stddef.h>
#include <stdint.h>

typedef status_t (*action_handler_t)(void);
status_t action_register(uint8_t id, action_handler_t handler);
status_t action_handler(
    size_t input_size,
    uint8_t const *const input_buffer,
    size_t *const output_size,
    uint8_t *const output_buffer);

#endif /* APP_ACTION_H_ */
