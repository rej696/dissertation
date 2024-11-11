#include "app/telemetry.h"

#include "utils/dbc_assert.h"
#include "utils/status.h"

#include <stddef.h>
#include <stdint.h>

static telemetry_handler_t telemetry_map[256] = {0};

status_t telemetry_register(uint8_t id, telemetry_handler_t handler)
{
    DBC_REQUIRE(handler != NULL);

    if (telemetry_map[id] != NULL) {
        return TELEMETRY_STATUS_INVALID_HANDLER_REGISTRATION;
    }

    telemetry_map[id] = handler;
    return STATUS_OK;
}

status_t telemetry_handler(
    size_t input_size,
    uint8_t const *const input_buffer,
    size_t *const output_size,
    uint8_t *const output_buffer)
{
    DBC_REQUIRE(input_buffer != NULL);
    DBC_REQUIRE(output_buffer != NULL);
    if (input_size != 1) {
        return TELEMETRY_STATUS_INVALID_PAYLOAD_SIZE;
    }

    uint8_t const id = input_buffer[0];

    if (telemetry_map[id] == NULL) {
        return TELEMETRY_STATUS_INVALID_TELEMETRY_ID;
    }

    return telemetry_map[id](output_size, output_buffer);
}
