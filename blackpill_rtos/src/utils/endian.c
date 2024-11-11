
#include "utils/endian.h"

void endian_u32_from_network(uint8_t const *const buffer, uint32_t *const value)
{
    *value = ((uint32_t)(buffer[0] << 24) & 0xFF000000) | ((buffer[1] << 16) & 0xFF0000)
             | ((buffer[2] << 8) & 0xFF00) | (buffer[3] & 0xFF);
}

void endian_u32_to_network(uint32_t const value, uint8_t *const buffer)
{
    buffer[0] = (uint8_t)(value >> 24) & 0xFF;
    buffer[1] = (uint8_t)(value >> 16) & 0xFF;
    buffer[2] = (uint8_t)(value >> 8) & 0xFF;
    buffer[3] = (uint8_t)value & 0xFF;
}
