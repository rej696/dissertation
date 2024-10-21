#ifndef RESULT_H_
#define RESULT_H_

#include <stdint.h>
#include "utils/status.h"

typedef struct {
    status_t status;
    uint8_t value;
} u8_result_t;

typedef struct {
    status_t status;
    uint32_t value;
} u32_result_t;


#endif /* RESULT_H_ */