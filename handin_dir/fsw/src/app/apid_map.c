
#include "app/action.h"
#include "app/app_config.h"
#include "app/parameter.h"
#include "app/spacepacket.h"
#include "app/telemetry.h"

apid_handler_t apid_handler_map[APID_HANDLER_MAP_SIZE] = {
    [0] = action_handler,
    [1] = get_parameter_handler,
    [2] = set_parameter_handler,
    [3] = telemetry_handler,
};
