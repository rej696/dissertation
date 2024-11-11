#include "app/action.h"

#include "utils/dbc_assert.h"
#include "utils/status.h"

#include <stddef.h>
#include <stdint.h>

static action_handler_t action_map[256] = {0};

status_t action_register(uint8_t id, action_handler_t handler)
{
    DBC_REQUIRE(handler != NULL);

    if (action_map[id] != NULL) {
        return ACTION_STATUS_INVALID_HANDLER_REGISTRATION;
    }

    action_map[id] = handler;
    return STATUS_OK;
}

status_t action_handler(
    size_t input_size,
    uint8_t const *const input_buffer,
    size_t *const output_size,
    uint8_t *const output_buffer)
{
    DBC_REQUIRE(input_buffer != NULL);
    DBC_REQUIRE(output_buffer != NULL);
    if (input_size != 1) {
        return ACTION_STATUS_INVALID_PAYLOAD_SIZE;
    }

    uint8_t const id = input_buffer[0];

    if (action_map[id] == NULL) {
        return ACTION_STATUS_INVALID_ACTION_ID;
    }

    /* Actions don't return data */
    *output_size = 0;
    return action_map[id]();
}
