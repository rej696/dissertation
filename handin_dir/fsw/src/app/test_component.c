
#include "app/test_component.h"

#include "utils/dbc_assert.h"
#include "utils/debug.h"
#include "utils/endian.h"
#include "utils/status.h"

#include <stddef.h>
#include <stdint.h>

/*******************************
 * Private Variables
 *******************************/
static uint8_t u8_param = 0;
static uint32_t u32_param = 0;

/*******************************
 * Actions
 *******************************/

status_t test_component_print_hello(void)
{
    debug_str("Hello University of Bath!");
    return STATUS_OK;
}

status_t test_component_print_u8_param(void)
{
    DEBUG_INT("Printing u8 param:", u8_param);
    return STATUS_OK;
}

status_t test_component_print_u32_param(void)
{
    DEBUG_INT("Printing u32 param:", u32_param);
    return STATUS_OK;
}

status_t test_component_print_sum(void)
{
    DEBUG_INT("Printing u32 param + u8 param:", u32_param + u8_param);
    return STATUS_OK;
}

/*******************************
 * Parameters
 *******************************/

status_t test_component_get_u8_param(size_t *const size, uint8_t *const output)
{
    DBC_REQUIRE(size != NULL);
    DBC_REQUIRE(output != NULL);

    *size = 1;
    *output = u8_param;

    return STATUS_OK;
}

status_t test_component_set_u8_param(size_t size, uint8_t const *const input)
{
    DBC_REQUIRE(input != NULL);

    if (size != 1) {
        DEBUG("Invalid arguments for set_u8_param", PARAMETER_STATUS_INVALID_PAYLOAD_SIZE);
        return PARAMETER_STATUS_INVALID_PAYLOAD_SIZE;
    }
    u8_param = *input;
    return STATUS_OK;
}

status_t test_component_get_u32_param(size_t *const size, uint8_t *const output)
{
    DBC_REQUIRE(size != NULL);
    DBC_REQUIRE(output != NULL);

    *size = 4;
    endian_u32_to_network(u32_param, output);
    return STATUS_OK;
}

status_t test_component_set_u32_param(size_t size, uint8_t const *const input)
{
    DBC_REQUIRE(input != NULL);

    if (size != 4) {
        DEBUG("Invalid arguments for set_u32_param", PARAMETER_STATUS_INVALID_PAYLOAD_SIZE);
        return PARAMETER_STATUS_INVALID_PAYLOAD_SIZE;
    }
    endian_u32_from_network(input, &u32_param);
    return STATUS_OK;
}

/*******************************
 * Telemetry
 *******************************/

status_t test_component_tlm_sum(size_t *const size, uint8_t *const output)
{
    DBC_REQUIRE(size != NULL);
    DBC_REQUIRE(output != NULL);

    *size = 4;
    endian_u32_to_network(u32_param + u8_param, output);
    return STATUS_OK;
}
