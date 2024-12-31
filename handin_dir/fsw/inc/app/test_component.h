#ifndef TEST_COMPONENT_H_
#define TEST_COMPONENT_H_

#include "utils/status.h"

#include <stddef.h>
#include <stdint.h>

/*******************************
 * Actions
 *******************************/

status_t test_component_print_hello(void);
status_t test_component_print_u8_param(void);
status_t test_component_print_u32_param(void);
status_t test_component_print_sum(void);

/*******************************
 * Parameters
 *******************************/

status_t test_component_get_u8_param(size_t *const size, uint8_t *const output);
status_t test_component_set_u8_param(size_t size, uint8_t const *const input);

status_t test_component_get_u32_param(size_t *const size, uint8_t *const output);
status_t test_component_set_u32_param(size_t size, uint8_t const *const input);

/*******************************
 * Telemetry
 *******************************/

status_t test_component_tlm_sum(size_t *const size, uint8_t *const output);

#endif /* TEST_COMPONENT_H_ */
