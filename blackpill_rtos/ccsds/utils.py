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


def blackbox_generator():
    try:
        while True:
            yield random.randint(0, 255)
    except KeyboardInterrupt:
        raise StopIteration
