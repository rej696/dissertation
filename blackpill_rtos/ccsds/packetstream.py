from spacepackets.ccsds.spacepacket import SpacePacketHeader, PacketType
from ccsds.kiss import kiss_pack, kiss_unpack
from ccsds.utils import checksum, take

# Length of data is max size of frame minus headers and trailers
# DATA_LEN_MAX = 0x3FF - 2 - 6
DATA_LEN_MAX = 6

# APIDs
ACTION_APID = 0
GET_PARAM_APID = 1
SET_PARAM_APID = 2
TELEM_APID = 3


class SppValidityFlags:
    SPP_VALID_VERSION = 0b000
    SPP_INVALID_VERSION = 0b001
    SPP_VALID_SEC_HDR = False
    SPP_INVALID_SEC_HDR = True
    SPP_INVALID_APID = 0xFF
    SPP_INVALID_LENGTH = 0xFF

    def __init__(self, config_byte):
        self._frame = bool((config_byte >> 7) & 0x01)
        self._checksum = bool((config_byte >> 6) & 0x01)
        self._spp_version = bool((config_byte >> 5) & 0x01)
        self._spp_type = bool((config_byte >> 4) & 0x01)
        self._spp_sec_hdr = bool((config_byte >> 3) & 0x01)
        self._spp_apid = bool((config_byte >> 2) & 0x01)
        self._spp_data_length = bool((config_byte >> 1) & 0x01)
        self._spp_seq_count = bool(config_byte & 0x01)

    def trigger(self) -> int:
        return 0x05

    def frame(self, bytes_: bytearray) -> bytearray:
        """Perform kiss framing depending on validity flags"""
        if self._frame:
            return kiss_pack(bytes_)
        return bytes_

    def checksum(self, bytes_: bytearray) -> bytearray:
        """Perform a checksum depending on validity flags"""
        result = checksum(bytes_)
        if self._checksum:
            return result
        csum = result[-1]
        result[-1] = (csum + 1) % 256
        return result

    def spp_version(self) -> int:
        """Return the version of the spacepacket depending on validity flags"""
        return self.SPP_VALID_VERSION if self._spp_version else self.SPP_INVALID_VERSION

    def spp_type(self) -> PacketType:
        """Return the type of the spacepacket depending on validity flags"""
        return PacketType.TC if self._spp_type else PacketType.TM

    def spp_sec_hdr(self) -> int:
        """Return the sec_hdr field of the spacepacket depending on validity flags"""
        return self.SPP_VALID_SEC_HDR if self._spp_sec_hdr else self.SPP_INVALID_SEC_HDR

    def spp_apid(self, value) -> int:
        """Return the sec_hdr field of the spacepacket depending on validity flags"""
        return value if self._spp_apid else self.SPP_INVALID_APID

    def spp_data_len(self, value) -> int:
        return value if self._spp_data_length else self.SPP_INVALID_LENGTH

    def spp_seq_count(self, value) -> int:
        return value if self._spp_seq_count else seq_count_dec(value)

    def sph_create(self, apid, data_len, seq_count) -> SpacePacketHeader:
        return SpacePacketHeader(
            packet_type=self.spp_type(),
            apid=self.spp_apid(apid),
            data_len=self.spp_data_len(data_len),
            seq_count=self.spp_seq_count(seq_count),
            sec_header_flag=self.spp_sec_hdr(),
            ccsds_version=self.spp_version()
        )


def seq_count_inc(value):
    return value + 1 if value < 16383 else 0


def seq_count_dec(value):
    return value - 1 if value > 0 else 16383


def spacepackets2bytes(spacepacket_stream):
    for flags, sph, data in spacepacket_stream:
        for byte in flags.frame(flags.checksum(sph.pack() + data)):
            yield byte


def spacepacket_factory(field_stream):
    seq_count = 0
    for flags, apid, data_len, data in field_stream:
        sph = flags.sph_create(apid, data_len, seq_count)
        seq_count = seq_count_inc(seq_count)
        yield flags, sph, data


def bytes2fields(byte_stream):
    try:
        while True:
            # Read a byte into the validity flags
            flags = SppValidityFlags(list(take(byte_stream, 1))[0])

            # FIXME Perhaps start with known good values e.g. actions and telemetry don't need more data etc.
            config_byte = list(take(byte_stream, 1))[0]
            apid = (config_byte >> 4) & 0x0F
            handler_id = config_byte & 0x0F

            data = bytearray([handler_id])
            data_len = 0  # Spacepacket data_len field is len(data) - 1
            if apid == SET_PARAM_APID:
                config_byte = list(take(byte_stream, 1))[0]
                payload_len = config_byte & 0x0F
                payload = bytearray(take(byte_stream, payload_len))
                data = data + payload
                data_len += payload_len

            yield flags, apid, data_len, data
    except (StopIteration, RuntimeError):
        return
        # raise StopIteration
