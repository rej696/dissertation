#ifndef APP_SPACEPACKET_H_
#define APP_SPACEPACKET_H_

#include "utils/cbuf.h"
#include "utils/status.h"

#include <stddef.h>
#include <stdint.h>

#define SPACEPACKET_VERSION          (0)
#define SPACEPACKET_TYPE_TM          (0)
#define SPACEPACKET_TYPE_TC          (1)
#define SPACEPACKET_SEC_HDR_DISABLED (0)
#define SPACEPACKET_SEC_HDR_ENABLED  (1)
#define SPACEPACKET_HDR_SIZE         (6)
#define SPACEPACKET_DATA_MAX_SIZE    (6)

#define SPACEPACKET_SEQ_FLAGS_CONTINUATION (0x0)
#define SPACEPACKET_SEQ_FLAGS_FIRST        (0x1)
#define SPACEPACKET_SEQ_FLAGS_LAST         (0x2)
#define SPACEPACKET_SEQ_FLAGS_UNSEGMENTED  (0x3)

#if 0
typedef struct __attribute__((packed)) {
    uint8_t version : 3;
    uint8_t type : 1;
    uint8_t sec_hdr : 1;
    uint16_t apid : 11;
    uint8_t sequence_flags : 2;
    uint16_t sequence_count : 14;
    uint16_t data_length : 16;
} spacepacket_hdr_t;
#endif
typedef struct {
    uint8_t version;
    uint8_t type;
    uint8_t sec_hdr;
    uint16_t apid;
    uint8_t sequence_flags;
    uint16_t sequence_count;
    uint16_t data_length;
} spacepacket_hdr_t;

#define APID_HANDLER_MAP_SIZE (256)

typedef status_t (*apid_handler_t)(size_t, uint8_t const *const, size_t *, uint8_t *const);
extern apid_handler_t apid_handler_map[APID_HANDLER_MAP_SIZE];

status_t spacepacket_process(
    size_t const packet_size,
    uint8_t const packet_buffer[packet_size],
    size_t *const response_size,
    uint8_t *const response_buffer);

#endif /* APP_SPACEPACKET_H_ */
