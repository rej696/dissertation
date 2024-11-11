
#include "app/spacepacket.h"

#include "app/app_config.h"
#include "utils/dbc_assert.h"
#include "utils/status.h"
#include "utils/debug.h"

#include <stddef.h>
#include <stdint.h>

static status_t validate_hdr(spacepacket_hdr_t const *const hdr)
{
    if (hdr->version != SPACEPACKET_VERSION) {
        return SPACEPACKET_STATUS_INVALID_VERSION;
    }
    if (hdr->type != SPACEPACKET_TYPE_TC) {
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

status_t spacepacket_process(size_t const size, uint8_t const buffer[size])
{
    DBC_REQUIRE(buffer != NULL);
    if (size < 6) {
        DEBUG("Spacepacket buffer too short", SPACEPACKET_STATUS_BUFFER_UNDERFLOW);
    }

    spacepacket_hdr_t const *const hdr = (spacepacket_hdr_t const *const)&buffer[0];

    // Validate Packet Header
    status_t status = validate_hdr(hdr);
    if (status != STATUS_OK) {
        DEBUG("Invalid spacepacket header", status);
        return status;
    }

    // handle application data
    apid_handler_t apid_handler = apid_handler_map[hdr->apid];
    if (apid_handler == NULL) {
        DEBUG("No handler for APID", SPACEPACKET_STATUS_INVALID_APID_HANDLER);
        return SPACEPACKET_STATUS_INVALID_APID_HANDLER;
    }

    size_t output_size = 0;
    uint8_t output_buffer[256] = {0};
    status = apid_handler(size - 6, &buffer[6], &output_size, output_buffer);

    // TODO build up output buffer and telemetry space packet

    return status;
}
