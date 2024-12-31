KISS_FEND = 0xC0
KISS_FESC = 0xDB
KISS_TFEND = 0xDC
KISS_TFESC = 0xDD


def kiss_pack(data: bytearray) -> bytearray:
    frame = []
    for byte in data:
        if byte == KISS_FEND:
            frame.append(KISS_FESC)
            frame.append(KISS_TFEND)
        elif byte == KISS_FESC:
            frame.append(KISS_FESC)
            frame.append(KISS_TFESC)
        else:
            frame.append(byte)
    frame.append(KISS_FEND)
    return bytearray(frame)


def kiss_unpack(frame: bytearray) -> bytearray:
    data = []
    escape = False
    for byte in frame:
        if byte == KISS_FEND:
            continue
        elif byte == KISS_FESC:
            escape = True
        elif byte == KISS_TFEND:
            if escape:
                byte = KISS_FEND
            escape = False
        elif byte == KISS_TFESC:
            if escape:
                byte = KISS_FESC
            escape = False
        else:
            escape = False

        if not escape:
            data.append(byte)

    return bytearray(data)
