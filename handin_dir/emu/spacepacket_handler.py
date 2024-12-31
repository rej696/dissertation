import copy
import itertools
from pgf.utils import take, raw_input_stream
from pgf.packetstream import PacketStream


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
        self.packets = None
        self.packets_available = False
        self.counter = 0

    def append_packet_generator(self, generator):
        if self.packets:
            self.packets = itertools.chain(self.packets, generator)
        else:
            self.packets = generator
        self.packets_available = True

    def set_input(self, input_bytes):
        """
        Read from a iterable bytes object through the spacepacket grammar into the packet queue
        """
        self.append_packet_generator(
            SpacepacketEntry(handler.trigger(), handler.pack())
            for handler in PacketStream.from_bytestream((b for b in input_bytes))
        )

    def set_raw_input(self, input_bytes):
        """
        Insert a raw bytes object into the packet queue with a trigger
        """
        self.append_packet_generator(
            SpacepacketEntry(trigger, data)
            for trigger, data in raw_input_stream((b for b in input_bytes))
        )

    def packet_generator(self):
        for packet in self.packets:
            self.counter = 0

            while self.counter <= packet.trigger:
                self.counter += 1
                yield None

            yield packet.packet

        while self.counter < 32:
            self.counter += 1
            yield None

        raise OutOfPacketsException("Ran out of Spacepackets to send")
