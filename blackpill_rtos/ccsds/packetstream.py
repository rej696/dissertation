from spacepackets.ccsds.spacepacket import SpacePacketHeader, PacketType, SequenceFlags
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

def seq_count_inc(value):
    return value + 1 if value < 16383 else 0


def seq_count_dec(value):
    return value - 1 if value > 0 else 16383


class PacketStream:
    SPP_VALID_VERSION = 0b000
    SPP_INVALID_VERSION = 0b001
    SPP_VALID_SEC_HDR = False
    SPP_INVALID_SEC_HDR = True
    SPP_INVALID_APID = 0xFF
    SPP_INVALID_LENGTH = 0xFF

    def __init__(self, byte_stream):
        self.seq_count = 0

        # Initialise with no error conditions
        self._frame = True
        self._checksum = True
        self._spp_version = True
        self._spp_type = True
        self._spp_sec_hdr = True
        self._spp_apid = True
        self._spp_data_length = True
        self._spp_seq_count = True
        self._spp_seq_flags = True
        self._handler_id_valid = True
        self._payload_valid = True

        config_byte = list(take(byte_stream, 1))[0]
        self._trigger = (config_byte >> 4) & 0xF

        # set error conditions depending on config byte
        match (config_byte & 0xF):
            case 0x0: pass  # 0 is fully valid packet
            case 0x1: self._frame = False
            case 0x2: self._checksum = False
            case 0x3: self._spp_version = False
            case 0x4: self._spp_type = False
            case 0x5: self._spp_sec_hdr = False
            case 0x6: self._spp_apid = False
            case 0x7: self._spp_data_length = False
            case 0x8: self._spp_seq_count = False
            case 0x9: self._spp_seq_flags = False
            # TODO use other error conditions?
            case 0xB: self._payload_valid = False
            case 0xC: pass
            case 0xD: pass
            case 0xE: pass
            case 0xF: pass


        # Start with known good values e.g. actions and telemetry don't need more data etc.
        config_byte = list(take(byte_stream, 1))[0]
        self.apid = (config_byte >> 4) & 0x03
        self.handler_id = config_byte & 0x0F

        # Handle handler_id error condition
        payload = bytearray()
        payload_len = 0

        config_byte = list(take(byte_stream, 1))[0]
        if self._payload_valid:
            self.data = bytearray([self.handler_id])
            self.data_len = 0  # Spacepacket data_len field is len(data) - 1
            # only set param has payload data
            if self.apid == SET_PARAM_APID:
                # read a small number from the config byte to increase likeliness of validity (i.e. < 6)
                self.data_len += config_byte & 0x07
                self.data += bytearray(take(byte_stream, self.data_len))
        else:
            # handle invalid payload data error condition
            self.data_len = config_byte + 1
            self.data = bytearray(take(byte_stream, self.data_len))

        # self._frame = bool((config_byte >> 7) & 0x01)
        # self._checksum = bool((config_byte >> 6) & 0x01)
        # self._spp_version = bool((config_byte >> 5) & 0x01)
        # self._spp_type = bool((config_byte >> 4) & 0x01)
        # self._spp_sec_hdr = bool((config_byte >> 3) & 0x01)
        # self._spp_apid = bool((config_byte >> 2) & 0x01)
        # self._spp_data_length = bool((config_byte >> 1) & 0x01)
        # self._spp_seq_count = bool(config_byte & 0x01)

    def trigger(self) -> int:
        return self._trigger

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

    def spp_seq_flags(self) -> SequenceFlags:
        return SequenceFlags.UNSEGMENTED if self._spp_seq_flags else SequenceFlags.CONTINUATION_SEGMENT

    @property
    def sph(self) -> SpacePacketHeader:
        return SpacePacketHeader(
            packet_type=self.spp_type(),
            apid=self.spp_apid(self.apid),
            data_len=self.spp_data_len(self.data_len),
            seq_flags=self.spp_seq_flags(),
            seq_count=self.spp_seq_count(self.seq_count),
            sec_header_flag=self.spp_sec_hdr(),
            ccsds_version=self.spp_version()
        )

    def pack(self) -> bytearray:
        return self.frame(self.checksum(self.sph.pack() + self.data))

    def to_bytestream(self):
        """Generates a stream of bytes"""
        for byte in self.pack():
            yield byte

    @staticmethod
    def from_bytestream(bytestream):
        """Generates a stream of PacketStream object from a bytestream"""
        try:
            while True:
                # Parse the bytestream into the PacketStream object
                packet = PacketStream(bytestream)

                yield packet
        except (StopIteration, RuntimeError):
            return
