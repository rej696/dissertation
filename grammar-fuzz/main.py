from spacepackets.ccsds.spacepacket import SpacePacketHeader, PacketType
from ccsds_sdlp import TcSpaceDataLinkProtocolHeader
# from spacepackets.uslp import PrimaryHeader, SourceOrDestField, ProtocolCommandFlag, BypassSequenceControlFlag, TransferFrame, TransferFrameDataField,
import random


def take(iter, n):
    for _ in range(n):
        yield next(iter)
    # for _, x in zip(range(n), iter):
    #     yield x


APID_LIST = list(range(4))
SCID_LIST = list(range(4))
VCID_LIST = list(range(4))
VALID_SEQ_COUNT = 1
INVALID_SEQ_COUNT = 2
# Length of data is max size of frame minus headers and trailers
DATA_LEN_MAX = 0x3FF - 5 - 2 - 6


def spacepackets2bytes(spacepacket_stream):
    for sdlph, sph, data in spacepacket_stream:
        for byte in sdlph.pack() + sph.pack() + data:
            yield byte


def spacepacket_factory(field_stream):
    seq_count = 0
    for scid, vcid, apid, data_len, data in field_stream:
        sph = SpacePacketHeader(
            packet_type=PacketType.TC, apid=apid, seq_count=seq_count, data_len=data_len - 1)
        sdlph = TcSpaceDataLinkProtocolHeader(
            scid=scid, vcid=vcid, frame_len=(data_len + 5 + 2), frame_seq_num=seq_count)
        seq_count = seq_count + 1 if seq_count < 16383 else 0
        yield sdlph, sph, data


def bytes2fields(byte_stream):
    try:
        while True:
            config_byte = list(take(byte_stream, 1))[0]
            apid = APID_LIST[(config_byte >> 6) & 0x03]
            seq_count = VALID_SEQ_COUNT if (
                config_byte >> 5) & 0x01 else INVALID_SEQ_COUNT
            scid = SCID_LIST[(config_byte >> 4) & 0x03]
            vcid = VCID_LIST[(config_byte >> 2) & 0x03]

            # get 10 bits for data_len
            data_len = (((config_byte & 0x03) << 8)
                        | list(take(byte_stream, 1))[0])

            # Cap data length
            if data_len > DATA_LEN_MAX:
                data_len = DATA_LEN_MAX

            data = bytearray(take(byte_stream, data_len))

            yield scid, vcid, apid, data_len, data
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
    for sdlp, spp, data in spacepacket_factory(bytes2fields(blackbox_generator())):
        print(sdlp)
        print(spp)
        print(bytearray(spacepackets2bytes([(sdlp, spp, data)])).hex(" "))
        input("again?")
