from spacepackets.ccsds.spacepacket import SpacePacketHeader, PacketType
import random

def take(iter, n):
    for _ in range(n):
        yield next(iter)
    # for _, x in zip(range(n), iter):
    #     yield x


APID_LIST = list(range(8))
VALID_SEQ_COUNT = 1
INVALID_SEQ_COUNT = 2
DATA_LEN_MAX = 256

def ccsds_frame_factory(byte_stream):


def spacepackets2bytes(spacepacket_stream):
    for sph, data in spacepacket_stream:
        for byte in sph.pack() + data:
            yield byte

def spacepacket_factory(field_stream):
    seq_count = 0
    for apid, data_len, data in field_stream:
        sph = SpacePacketHeader(packet_type=PacketType.TC, apid=apid, seq_count=seq_count, data_len=data_len)
        seq_count = seq_count + 1 if seq_count < 16383 else 0
        yield sph, data


def bytes2fields(byte_stream):
    try:
        while True:
            config_byte = list(take(byte_stream, 1))[0]
            apid = APID_LIST[(config_byte >> 5) & 0x07]
            seq_count = VALID_SEQ_COUNT if (config_byte >> 4) & 0x01 else INVALID_SEQ_COUNT

            data_len = int.from_bytes(bytearray(take(byte_stream, 2)))

            # Cap data length
            if data_len > DATA_LEN_MAX:
                data_len = DATA_LEN_MAX

            data = bytearray(take(byte_stream, data_len + 1))

            yield apid, data_len, data
    except StopIteration:
        raise StopIteration

    # for byte in byte_stream:
    #     apid_bit = (byte >> 7) & 0x01
    #     if apid_bit:



def blackbox_generator():
    try:
        while True:
            # yield random.randbytes(1)
            yield random.randint(0, 255)
    except KeyboardInterrupt:
        raise StopIteration

if __name__ == "__main__":
    for spp, data in spacepacket_factory(bytes2fields(blackbox_generator())):
        print(spp)
        print(bytearray(spacepackets2bytes([(spp, data)])).hex(" "))
        input("again?")

