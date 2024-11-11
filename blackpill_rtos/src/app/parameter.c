#include "app/parameter.h"

#include "utils/dbc_assert.h"
#include "utils/status.h"

#include <stddef.h>
#include <stdint.h>

static parameter_handler_t parameter_map[256] = {0};

status_t parameter_register(uint8_t id, parameter_handler_t handler)
{
    DBC_REQUIRE(handler.set != NULL);
    DBC_REQUIRE(handler.get != NULL);

    if ((parameter_map[id].get != NULL) || (parameter_map[id].set != NULL)) {
        return PARAMETER_STATUS_INVALID_HANDLER_REGISTRATION;
    }

    parameter_map[id] = handler;
    return STATUS_OK;
}

status_t get_parameter_handler(
    size_t input_size,
    uint8_t const *const input_buffer,
    size_t *const output_size,
    uint8_t *const output_buffer)
{
    DBC_REQUIRE(input_buffer != NULL);
    DBC_REQUIRE(output_buffer != NULL);
    if (input_size != 1) {
        return PARAMETER_STATUS_INVALID_PAYLOAD_SIZE;
    }

    uint8_t const id = input_buffer[0];

    if (parameter_map[id].get == NULL) {
        return PARAMETER_STATUS_INVALID_PARAMETER_ID;
    }

    return parameter_map[id].get(output_size, output_buffer);
}

status_t set_parameter_handler(
    size_t input_size,
    uint8_t const *const input_buffer,
    size_t *const output_size,
    uint8_t *const output_buffer)
{
    DBC_REQUIRE(input_buffer != NULL);
    DBC_REQUIRE(output_buffer != NULL);
    if (input_size < 2) {
        return PARAMETER_STATUS_INVALID_PAYLOAD_SIZE;
    }

    uint8_t const id = input_buffer[0];

    if (parameter_map[id].set == NULL) {
        return PARAMETER_STATUS_INVALID_PARAMETER_ID;
    }

    *output_size = 0;
    return parameter_map[id].set(input_size - 1, &input_buffer[1]);
}
