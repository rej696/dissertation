#ifndef APP_KISS_FRAME_H_
#define APP_KISS_FRAME_H_

#include "utils/cbuf.h"

#include <stdbool.h>
#include <stdint.h>

#define KISS_FEND  (0xC0U)
#define KISS_FESC  (0xDBU)
#define KISS_TFEND (0xDCU)
#define KISS_TFESC (0xDDU)

bool kiss_frame_unpack(cbuf_t *const cbuf, size_t *const count, uint8_t *const output);

void kiss_frame_pack(
    size_t const input_size,
    uint8_t const input[input_size],
    size_t *const output_size,
    uint8_t *const output);

#endif /* APP_KISS_FRAME_H_ */
