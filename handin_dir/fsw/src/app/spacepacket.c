
#include "app/spacepacket.h"

#include "app/app_config.h"
#include "utils/dbc_assert.h"
#include "utils/debug.h"
#include "utils/endian.h"
#include "utils/status.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Telemetries */
static uint32_t out_of_seq_count = 0;
static uint32_t csum_error_count = 0;
static uint16_t last_seq_count_recv = 0;

static status_t build_packet(
    spacepacket_hdr_t *const hdr,
    size_t const data_size,
    uint8_t const data_buffer[data_size],
    size_t *const output_size,
    uint8_t *const output_buffer)
{
    DBC_REQUIRE(hdr != NULL);
    DBC_REQUIRE(data_buffer != NULL);
    DBC_REQUIRE(data_size < SPACEPACKET_DATA_MAX_SIZE);
    DBC_REQUIRE(output_buffer != NULL);
    DBC_REQUIRE(hdr->data_length == data_size - 1);
    DBC_REQUIRE(hdr->type == SPACEPACKET_TYPE_TM);

    /* Copy spacepacket header into buffer */
    output_buffer[0] = (hdr->version << 5) & 0xE0;
    output_buffer[0] |= (hdr->type << 4) & 0x10;
    output_buffer[0] |= (hdr->sec_hdr << 3) & 0x08;
    output_buffer[0] |= (hdr->apid >> 8) & 0x07;
    output_buffer[1] = (uint8_t)(hdr->apid & 0xFF);
    output_buffer[2] = (hdr->sequence_flags << 6) & 0xC0;
    output_buffer[2] = (hdr->sequence_count >> 8) & 0x3F;
    output_buffer[3] = (uint8_t)(hdr->sequence_count & 0xFF);
    output_buffer[4] = (uint8_t)((hdr->data_length >> 8) & 0xFF);
    output_buffer[5] = (uint8_t)(hdr->data_length & 0xFF);

    /* Copy spacepacket header into buffer */
    memcpy(&output_buffer[6], data_buffer, data_size);
    *output_size = data_size + SPACEPACKET_HDR_SIZE;

    return STATUS_OK;
}

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
        DEBUG_INT("Invalid spacepacket type", hdr->type);
        return SPACEPACKET_STATUS_INVALID_TYPE;
    }
    if (hdr->sec_hdr != SPACEPACKET_SEC_HDR_DISABLED) {
        /* Spacepacket secondary headers are not supported */
        return SPACEPACKET_STATUS_INVALID_SEC_HDR;
    }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
    if ((hdr->apid < SPACEPACKET_CONFIG_MIN_APID) || (hdr->apid > SPACEPACKET_CONFIG_MAX_APID)) {
        DEBUG_INT("Invalid APID", hdr->apid);
        return SPACEPACKET_STATUS_INVALID_APID;
    }
#pragma GCC diagnostic pop

    if (hdr->data_length > SPACEPACKET_DATA_MAX_SIZE) {
        return SPACEPACKET_STATUS_BUFFER_OVERFLOW;
    }

    /* Handle Sequence Counter */
    if (hdr->sequence_count != (last_seq_count_recv + 1)) {
        out_of_seq_count++;
    }
    last_seq_count_recv = hdr->sequence_count;

    return STATUS_OK;
}

static bool validate_checksum(size_t const size, uint8_t const buffer[size])
{
    DBC_REQUIRE(buffer != NULL);
    DBC_REQUIRE(size > SPACEPACKET_CHECKSUM_SIZE);

    /* Last byte is a checksum */
    size_t csum_idx = size - SPACEPACKET_CHECKSUM_SIZE;
    uint8_t csum_recv = buffer[csum_idx];
    uint8_t csum_calc = 0;
    for (size_t i = 0; i < csum_idx; ++i) {
        csum_calc = (csum_calc + buffer[i]) % 256;
    }
    return csum_calc == csum_recv;
}

status_t spacepacket_process(
    size_t const packet_size,
    uint8_t const packet_buffer[packet_size],
    size_t *const response_size,
    uint8_t *const response_buffer)
{
    DBC_REQUIRE(packet_buffer != NULL);
    DBC_REQUIRE(response_size != NULL);
    DBC_REQUIRE(response_buffer != NULL);

    if (packet_size < SPACEPACKET_HDR_SIZE) {
        DEBUG(
            "Not enough bytes in buffer for spacepacket header",
            SPACEPACKET_STATUS_BUFFER_UNDERFLOW);
        return SPACEPACKET_STATUS_BUFFER_UNDERFLOW;
    }

    spacepacket_hdr_t hdr = {0};
    status_t status = parse_hdr(SPACEPACKET_HDR_SIZE, &packet_buffer[0], &hdr);
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
    size_t data_size = packet_size - SPACEPACKET_HDR_SIZE - SPACEPACKET_CHECKSUM_SIZE;
    if (data_size != (size_t)hdr.data_length + 1) {
        if (data_size > hdr.data_length) {
            DEBUG(
                "Too many bytes in buffer for spacepacket data",
                SPACEPACKET_STATUS_BUFFER_OVERFLOW);
            return SPACEPACKET_STATUS_BUFFER_OVERFLOW;
        } else {
            DEBUG(
                "Not enough bytes in buffer for spacepacket data",
                SPACEPACKET_STATUS_BUFFER_UNDERFLOW);
            return SPACEPACKET_STATUS_BUFFER_UNDERFLOW;
        }
    }

    if (!validate_checksum(packet_size, packet_buffer)) {
        DEBUG(
            "Invalid checksum, discarding received spacepacket",
            SPACEPACKET_STATUS_INVALID_CHECKSUM);
        csum_error_count++;
        return SPACEPACKET_STATUS_INVALID_CHECKSUM;
    }

    uint8_t const *const data_buf = &packet_buffer[SPACEPACKET_HDR_SIZE];

    // handle application data
    apid_handler_t apid_handler = apid_handler_map[hdr.apid];
    if (apid_handler == NULL) {
        DEBUG("No handler for APID", SPACEPACKET_STATUS_INVALID_APID_HANDLER);
        return SPACEPACKET_STATUS_INVALID_APID_HANDLER;
    }

    size_t output_size = 0;
    uint8_t output_buffer[SPACEPACKET_DATA_MAX_SIZE] = {0};
    status = apid_handler(hdr.data_length + 1, data_buf, &output_size, &output_buffer[1]);
    if (status != STATUS_OK) {
        DEBUG("Failed to handle spacepacket data", status);
    }
    output_buffer[0] = (uint8_t)status;
    output_size += 1;

    spacepacket_hdr_t output_hdr = {
        .version = SPACEPACKET_VERSION,
        .type = SPACEPACKET_TYPE_TM,
        .sec_hdr = SPACEPACKET_SEC_HDR_DISABLED,
        .sequence_flags = SPACEPACKET_SEQ_FLAGS_UNSEGMENTED,
        .sequence_count = hdr.sequence_count, /* Use sequence number from received packet */
        .apid = hdr.apid,
        .data_length = (uint16_t)(output_size - 1),
    };

    status = build_packet(
        &output_hdr,
        output_size,
        &output_buffer[0],
        response_size,
        response_buffer);

    return status;
}

/* Telemetry Handlers */
status_t spacepacket_out_of_seq_count(size_t *const size, uint8_t *const output)
{
    DBC_REQUIRE(size != NULL);
    DBC_REQUIRE(output != NULL);

    *size = 4;
    endian_u32_to_network(out_of_seq_count, output);
    return STATUS_OK;
}

status_t spacepacket_csum_error_count(size_t *const size, uint8_t *const output)
{
    DBC_REQUIRE(size != NULL);
    DBC_REQUIRE(output != NULL);

    *size = 4;
    endian_u32_to_network(csum_error_count, output);
    return STATUS_OK;
}

status_t spacepacket_last_seq_count(size_t *const size, uint8_t *const output)
{
    DBC_REQUIRE(size != NULL);
    DBC_REQUIRE(output != NULL);

    *size = 4;
    endian_u32_to_network(csum_error_count, output);
    return STATUS_OK;
}
