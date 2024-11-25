
#include "app/spacepacket.h"

#include "app/app_config.h"
#include "utils/dbc_assert.h"
#include "utils/debug.h"
#include "utils/status.h"

#include <stddef.h>
#include <stdint.h>

static status_t parse_hdr(
    size_t const size,
    uint8_t const buffer[size],
    spacepacket_hdr_t *const hdr)
{
    DBC_REQUIRE(buffer != NULL);
    DBC_REQUIRE(hdr != NULL);

    if (size < 6) {
        DEBUG("Spacepacket buffer too short", SPACEPACKET_STATUS_BUFFER_UNDERFLOW);
        return SPACEPACKET_STATUS_BUFFER_UNDERFLOW;
    }

    hdr->version = (buffer[0] >> 5) & 0x7;
    hdr->type = (buffer[0] >> 4) & 0x1;
    hdr->sec_hdr = (buffer[0] >> 3) & 0x1;
    hdr->apid = (uint16_t)(((buffer[0] & 0x7) << 8) | buffer[1]);
    hdr->sequence_flags = (buffer[2] >> 6) & 0x3;
    hdr->sequence_count = (uint16_t)(((buffer[2] & 0x3F) << 8) | buffer[3]);
    hdr->data_length = (uint16_t)((buffer[4] << 8) | buffer[5]);

#if 0 /* Debug Spacepacket Header */
    uint8_t debug_buf[] = {
        hdr->version,
        hdr->type,
        hdr->sec_hdr,
        (uint8_t)hdr->apid,
        hdr->sequence_flags,
        (uint8_t)hdr->sequence_count,
        (uint8_t)hdr->data_length,
    };
    debug_hex(sizeof(debug_buf), debug_buf);
#endif
    return STATUS_OK;
}

static status_t validate_hdr(spacepacket_hdr_t const *const hdr)
{
    if (hdr->version != SPACEPACKET_VERSION) {
        return SPACEPACKET_STATUS_INVALID_VERSION;
    }
    if (hdr->type != SPACEPACKET_TYPE_TC) {
        DEBUG("Invalid spacepacket type", (status_t)hdr->type);
        return SPACEPACKET_STATUS_INVALID_TYPE;
    }
    if (hdr->sec_hdr != SPACEPACKET_SEC_HDR_DISABLED) {
        /* Spacepacket secondary headers are not supported */
        return SPACEPACKET_STATUS_INVALID_SEC_HDR;
    }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
    if ((hdr->apid < SPACEPACKET_CONFIG_MIN_APID) || (hdr->apid >= SPACEPACKET_CONFIG_MAX_APID)) {
        return SPACEPACKET_STATUS_INVALID_APID;
    }
#pragma GCC diagnostic pop

    return STATUS_OK;
}

/* status_t spacepacket_process(size_t const size, uint8_t const buffer[size]) */
status_t spacepacket_process(cbuf_t *const cbuf)
{
    DBC_REQUIRE(cbuf != NULL);

    if (cbuf_size(cbuf) < SPACEPACKET_HDR_SIZE) {
        DEBUG("Not enough bytes in buffer for spacepacket header", SPACEPACKET_STATUS_BUFFER_UNDERFLOW);
        return SPACEPACKET_STATUS_BUFFER_UNDERFLOW;
    }

    uint8_t hdr_buf[SPACEPACKET_HDR_SIZE] = {0};
    status_t status = cbuf_read(cbuf, SPACEPACKET_HDR_SIZE, hdr_buf);
    if (status != STATUS_OK) {
        DEBUG("Falied to read spacepacket header from cbuf", status);
        return status;
    }

    spacepacket_hdr_t hdr = {0};
    status = parse_hdr(SPACEPACKET_HDR_SIZE, &hdr_buf[0], &hdr);
    if (status != STATUS_OK) {
        DEBUG("Unable to parse spacepacket header", status);
        return status;
    }

    // Validate Packet Header
    status = validate_hdr(&hdr);
    if (status != STATUS_OK) {
        DEBUG("Invalid spacepacket header", status);
        return status;
    }

    /* Validate data size */
    if (cbuf_size(cbuf) <= hdr.data_length) {
        DEBUG("Not enough bytes in buffer for spacepacket data", SPACEPACKET_STATUS_BUFFER_UNDERFLOW);
        return SPACEPACKET_STATUS_BUFFER_UNDERFLOW;
    }

    uint8_t data_buf[SPACEPACKET_DATA_MAX_SIZE] = {0};
    status = cbuf_read(cbuf, hdr.data_length + 1, data_buf);
    if (status != STATUS_OK) {
        DEBUG("Falied to read spacepacket data from cbuf", status);
        return status;
    }

    // handle application data
    apid_handler_t apid_handler = apid_handler_map[hdr.apid];
    if (apid_handler == NULL) {
        DEBUG("No handler for APID", SPACEPACKET_STATUS_INVALID_APID_HANDLER);
        return SPACEPACKET_STATUS_INVALID_APID_HANDLER;
    }

    size_t output_size = 0;
    uint8_t output_buffer[256] = {0};
    status = apid_handler(hdr.data_length + 1, data_buf, &output_size, output_buffer);

    // TODO build up output buffer and telemetry space packet

    return status;
}
