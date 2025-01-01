#ifndef STATUS_H_
#define STATUS_H_

#if 0 /* If the STATUS_MAX can't fit into a uint8, toggle this if block */
#define STATUS_ENUM_GREATER_THAN_UINT8
#endif

typedef enum status {
    STATUS_OK = 0x00,
    STATUS_ERROR = 0x01,

    CBUF_STATUS_BUFFER_OVERFLOW = 0x10,
    CBUF_STATUS_CBUF_FULL,
    CBUF_STATUS_CBUF_EMPTY,

    SPACEPACKET_STATUS_INVALID_VERSION = 0x20,
    SPACEPACKET_STATUS_INVALID_TYPE,
    SPACEPACKET_STATUS_INVALID_SEC_HDR,
    SPACEPACKET_STATUS_INVALID_CHECKSUM,
    SPACEPACKET_STATUS_INVALID_APID,
    SPACEPACKET_STATUS_INVALID_APID_HANDLER,
    SPACEPACKET_STATUS_BUFFER_UNDERFLOW,
    SPACEPACKET_STATUS_BUFFER_OVERFLOW,

    ACTION_STATUS_INVALID_HANDLER_REGISTRATION = 0x30,
    ACTION_STATUS_INVALID_PAYLOAD_SIZE,
    ACTION_STATUS_INVALID_ACTION_ID,

    PARAMETER_STATUS_INVALID_HANDLER_REGISTRATION = 0x40,
    PARAMETER_STATUS_INVALID_PAYLOAD_SIZE,
    PARAMETER_STATUS_INVALID_PARAMETER_ID,

    TELEMETRY_STATUS_INVALID_HANDLER_REGISTRATION = 0x50,
    TELEMETRY_STATUS_INVALID_PAYLOAD_SIZE,
    TELEMETRY_STATUS_INVALID_TELEMETRY_ID,

    /* Used to identify the size of the status enum */
    STATUS_MAX,
} status_t;

#endif /* STATUS_H_ */