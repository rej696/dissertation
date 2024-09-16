from scapy.packet import Packet
from scapy.fields import LenField, ByteField, BitEnumField, BitField, XIntField, TrailerField, IntField


class PacketStream(Packet):
    name = "Packet Stream"
    field_desc = [
            XIntField("asm", 0x1acffc1d),
            IntField("length", 0),
            TrailerField(IntField("checksum", 0))
            ]




class TransferFrame(Packet):
    name = "CCSDS Transfer Frame"
    field_desc = [
            BitField("version", 0, 2),
            BitField("scid", 0, 10),
            BitField("vcid", 0, 3),
            BitField("ocf", 0, 1),
            ByteField("master_channel_frame_count", 0),
            ByteField("virtual_channel_frame_count", 0),
            BitField("secondary_header_flag", 0, 1),
            BitField("synch_flag", 0, 1),
            BitField("packet_order_flag", 0, 1),
            BitField("segment_length_id", 0, 2),
            BitField("first_header_pointer", 0, 11),
    ]


class SpacePacket(Packet):
    name = "Space Packet"
    fields_desc = [
        BitField("version", 0, 3),
        BitField("type", 0, 1),
        BitField("secondary_header_flag", 0, 1),
        BitField("apid", 0, 11),
        BitEnumField("sequence_flags", 3, 2, {
            0: "Continuation Segment", 1: "First Segment", 2: "Last Segment", 3: "Unsegmented"}),
        BitField("sequence_count", 0, 14),
        LenField("length", None, adjust=lambda x: x - 1)
    ]
