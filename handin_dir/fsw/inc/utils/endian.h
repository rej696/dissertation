#ifndef UTILS_ENDIAN_H_
#define UTILS_ENDIAN_H_

#include <stdint.h>

void endian_u32_from_network(uint8_t const *const buffer, uint32_t *const value);
void endian_u32_to_network(uint32_t const value, uint8_t *const buffer);

#endif
