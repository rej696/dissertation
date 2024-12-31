import random


def take(iter, n):
    """take generator for lazily reading a sequence from an iterator"""
    for _ in range(n):
        yield next(iter)


def checksum(data: bytearray) -> bytearray:
    """Simple 8bit modulo checksum"""
    output = []
    sum = 0
    for byte in data:
        output.append(byte)
        sum = (sum + byte) % 256

    output.append(sum)
    return bytearray(output)


def raw_input_stream(input):
    while True:
        try:
            # Take a config byte and read length/trigger values,
            # then read out length many bytes from the stream
            config_byte = list(take(input, 1))[0]
            trigger = (config_byte >> 4) & 0xF
            input_len = config_byte & 0xF
            yield trigger, bytearray(take(input, input_len))
        except (StopIteration, RuntimeError):
            break


def blackbox_generator():
    try:
        while True:
            yield random.randint(0, 255)
    except KeyboardInterrupt:
        raise StopIteration
