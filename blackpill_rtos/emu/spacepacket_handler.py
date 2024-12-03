import copy
import itertools
from spacepackets.ccsds.spacepacket import SpacePacketHeader, PacketType
from ccsds.kiss import kiss_pack, kiss_unpack
from ccsds.utils import checksum, take
from ccsds.packetstream import PacketStream


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

    def set_input_old(self, input_bytes):
        """
        Read from a iterable bytes object through the spacepacket grammar into the packet queue
        """
        self.input_bytes = copy.deepcopy(input_bytes)

        def input_iter():
            for b in input_bytes:
                yield b

        for handler in PacketStream.from_bytestream(input_iter()):
            self.packets.append(SpacepacketEntry(handler.trigger(), handler.pack()))

    def set_raw_input_old(self, input_bytes):
        """Insert a raw bytes object into the packet queue with a trigger"""
        if len(input_bytes) < 2:
            raise SpacepacketInvalidInputException

        self.packets.append(
            SpacepacketEntry(int(input_bytes[0]), bytearray(input_bytes[1:]))
        )

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
        # 3 bytes are the minimum required for the grammar parser
        # if len(input_bytes) < 3:
        #     raise SpacepacketInvalidInputException
        self.append_packet_generator(
                SpacepacketEntry(handler.trigger(), handler.pack())
                for handler in
                PacketStream.from_bytestream((b for b in input_bytes)))

    def set_raw_input(self, input_bytes):
        """Insert a raw bytes object into the packet queue with a trigger"""
        # if len(input_bytes) < 2:
        #     raise SpacepacketInvalidInputException

        def input_iter(input):
            while True:
                # Take a length byte and read out that many bytes from the stream
                try:
                    config_byte = list(take(input, 1))[0]
                    trigger = (config_byte >> 4) & 0xF
                    input_len = config_byte & 0xF
                    yield SpacepacketEntry(trigger, bytearray(take(input, input_len)))
                except (StopIteration, RuntimeError) as e:
                    break


        self.append_packet_generator(input_iter((b for b in input_bytes)))

    # def send_packet(self):
    #     self.counter += 1
    #     if self.packets_available:
    #         if self.counter > 0xF:
    #             self.counter = 0
    #             try:
    #                 packet = list(take(self.packets, 1))[0]
    #                 print(packet)
    #                 return packet
    #             except (StopIteration, RuntimeError) as e:
    #                 print(e)
    #                 self.packets_available = False
    #     else:
    #         if self.counter > 32:
    #             raise OutOfPacketsException("Ran out of Spacepackets to send")

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




        # if len(self.packets) <= 0:
        #     if self.counter > 32:
        #         raise OutOfPacketsException("Ran out of Spacepackets to send")
        #     return None
        # if self.packets[0].trigger <= self.counter:
        #     self.counter = 0
        #     packet = self.packets.pop(0).packet
        #     return packet
