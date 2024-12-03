import copy
from spacepackets.ccsds.spacepacket import SpacePacketHeader, PacketType
from ccsds.kiss import kiss_pack, kiss_unpack
from ccsds.utils import checksum, take
from ccsds.packetstream import spacepacket_factory, spacepackets2bytes, bytes2fields


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

        for flags, spp, data in spacepacket_factory(bytes2fields(input_iter())):
            self.packets.append(
                SpacepacketEntry(flags.trigger(), bytearray(spacepackets2bytes([(flags, spp, data)])))
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
            packet = self.packets.pop(0).packet
            print(packet)
            return packet
