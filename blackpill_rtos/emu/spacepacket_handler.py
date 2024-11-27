import copy
from spacepackets.ccsds.spacepacket import SpacePacketHeader, PacketType

APID_LIST = list(range(4))
SCID_LIST = list(range(4))
VCID_LIST = list(range(4))
# Length of data is max size of frame minus headers and trailers
DATA_LEN_MAX = 0x3FF - 5 - 2 - 6


def take(iter, n):
    for _ in range(n):
        yield next(iter)


def spacepackets2bytes(spacepacket_stream):
    # for sdlph, sph, data in spacepacket_stream:
    #     for byte in sdlph.pack() + sph.pack() + data:
    #         yield byte
    for sph, data in spacepacket_stream:
        for byte in sph.pack() + data:
            yield byte


def spacepacket_factory(field_stream):
    seq_count = 0
    for trigger, scid, vcid, apid, data_len, data in field_stream:
        sph = SpacePacketHeader(
            packet_type=PacketType.TC,
            apid=apid,
            seq_count=seq_count,
            data_len=data_len - 1,
        )
        # sdlph = TcSpaceDataLinkProtocolHeader(
        #     scid=scid, vcid=vcid, frame_len=(data_len + 5 + 2), frame_seq_num=seq_count)
        seq_count = seq_count + 1 if seq_count < 16383 else 0
        yield trigger, sph, data


# bytestream = 0x05, 0x00, 0x00 is valid action at action id 0
def bytes2fields(byte_stream):
    try:
        while True:
            # Take first byte as trigger counter
            trigger = list(take(byte_stream, 1))[0]

            config_byte = list(take(byte_stream, 1))[0]
            apid = APID_LIST[(config_byte >> 6) & 0x03]
            scid = SCID_LIST[(config_byte >> 4) & 0x03]
            vcid = VCID_LIST[(config_byte >> 2) & 0x03]

            # get 10 bits for data_len
            data_len = ((config_byte & 0x03) << 8) | list(take(byte_stream, 1))[0]

            # Cap data length
            if data_len > DATA_LEN_MAX:
                data_len = DATA_LEN_MAX

            data = bytearray(take(byte_stream, data_len))

            yield trigger, scid, vcid, apid, data_len, data
    except (StopIteration, RuntimeError):
        return
        # raise StopIteration


class OutOfPacketsException(Exception):
    pass


class SpacepacketInvalidInputException(Exception):
    pass


class SpacepacketEntry:
    def __init__(self, trigger, packet_bytes: bytearray):
        self.trigger = trigger + 1
        self.packet: bytearray = packet_bytes


class SpacepacketHandler:
    def __init__(self):
        self.input_bytes = None
        self.packets = []
        self.counter = 0

    def set_input(self, input_bytes):
        """
        Read from a iterable bytes object through the spacepacket grammar into the packet queue
        """
        self.input_bytes = copy.deepcopy(input_bytes)

        def input_iter():
            for b in input_bytes:
                yield b

        for trigger, spp, data in spacepacket_factory(bytes2fields(input_iter())):
            self.packets.append(
                SpacepacketEntry(trigger, bytearray(spacepackets2bytes([(spp, data)])))
            )

    def set_raw_input(self, input_bytes):
        """Insert a raw bytes object into the packet queue with a trigger"""
        if len(input_bytes) < 2:
            raise SpacepacketInvalidInputException

        self.packets.append(
            SpacepacketEntry(int(input_bytes[0]), bytearray(input_bytes[1:]))
        )

    def send_packet(self):
        self.counter += 1
        if len(self.packets) <= 0:
            if self.counter > 256:
                raise OutOfPacketsException("Ran out of Spacepackets to send")
            return None
        if self.packets[0].trigger <= self.counter:
            self.counter = 0
            # FIXME handle sending packet using uart?
            return self.packets.pop(0).packet


# packet_type=PacketType.TC, apid=0, seq_count=0, data_len=0
