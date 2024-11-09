#ifndef APP_SPACEPACKET_H_
#define APP_SPACEPACKET_H_

#include "utils/status.h"

#include <stddef.h>
#include <stdint.h>

#define SPACEPACKET_VERSION          (0)
#define SPACEPACKET_TYPE_TM          (0)
#define SPACEPACKET_TYPE_TC          (1)
#define SPACEPACKET_SEC_HDR_DISABLED (0)
#define SPACEPACKET_SEC_HDR_ENABLED  (1)

typedef struct __attribute__((packed)) {
    uint8_t version : 3;
    uint8_t type : 1;
    uint8_t sec_hdr : 1;
    uint16_t apid : 11;
    uint8_t sequence_flags : 2;
    uint16_t sequence_count : 14;
    uint16_t data_length : 16;
} spacepacket_hdr_t;

#define APID_HANDLER_MAP_SIZE (255)

typedef status_t (*apid_handler_t)(size_t, uint8_t const *const, size_t *, uint8_t *const);
extern apid_handler_t apid_handler_map[APID_HANDLER_MAP_SIZE];

status_t spacepacket_process(size_t const size, uint8_t const buffer[size]);

#endif /* APP_SPACEPACKET_H_ */
