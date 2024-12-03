#include "app/kiss_frame.h"

#include "utils/cbuf.h"
#include "utils/dbc_assert.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void kiss_frame_pack(
    size_t const input_size,
    uint8_t const input[input_size],
    size_t *const output_size,
    uint8_t *const output)
{
    DBC_REQUIRE(input != NULL);
    DBC_REQUIRE(output_size != NULL);
    DBC_REQUIRE(output != NULL);

    *output_size = 0U;
    for (size_t i = 0; i < input_size; ++i) {
        switch (input[i]) {
            case KISS_FEND: {
                output[*output_size] = KISS_FESC;
                *output_size += 1;
                output[*output_size] = KISS_TFEND;
                *output_size += 1;
                break;
            }
            case KISS_FESC: {
                output[*output_size] = KISS_FESC;
                *output_size += 1;
                output[*output_size] = KISS_TFESC;
                *output_size += 1;
                break;
            }
            default: {
                output[*output_size] = input[i];
                *output_size += 1;
                break;
            }
        }
    }
    output[*output_size] = KISS_FEND;
    *output_size += 1;
}

bool kiss_frame_unpack(cbuf_t *const cbuf, size_t *const count, uint8_t *const output)
{
    DBC_REQUIRE(cbuf != NULL);
    DBC_REQUIRE(count != NULL);
    DBC_REQUIRE(output != NULL);

    bool end_frame = false;
    bool frame_esc = false;
    while ((cbuf_size(cbuf) > 0) && (!end_frame)) {
        uint8_t byte = 0;
        cbuf_get(cbuf, &byte);
        switch (byte) {
            case KISS_FEND: {
                /* Ignore any back to back FEND bytes (i.e. no frame data parsed yet) */
                if (*count <= 0) {
                    continue;
                }

                end_frame = true;
                frame_esc = false;
                break;
            }
            case KISS_FESC: {
                end_frame = false;
                frame_esc = true;
                break;
            }
            case KISS_TFEND: {
                if (frame_esc) {
                    byte = KISS_FEND;
                }
                frame_esc = false;
                end_frame = false;
                break;
            }
            case KISS_TFESC: {
                if (frame_esc) {
                    byte = KISS_FESC;
                }
                frame_esc = false;
                end_frame = false;
                break;
            }
            default: {
                /* parse data normally */
                frame_esc = false;
                end_frame = false;
                break;
            }
        }
        if (!frame_esc && !end_frame) {
            if (*count >= CBUF_SIZE) {
                /* reset packet buffer if will overflow */
                *output = 0;
                return false;
            }
            /* Write byte to output buffer */
            output[*count] = byte;
            *count += 1;
        }
    }
    return end_frame;
}
