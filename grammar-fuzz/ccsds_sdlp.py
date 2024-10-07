from spacepackets.exceptions import BytesTooShortError
from typing import Final, Optional, Self
import struct

TC_HEADER_LEN: Final[int] = 5
TM_HEADER_LEN: Final[int] = 6
FEC_LEN: Final[int] = 2

VERSION_MASK: Final[int] = 0xC000
VERSION_OFFSET: Final[int] = 14

BYPASS_FLAG_MASK: Final[int] = 0x2000
BYPASS_FLAG_OFFSET: Final[int] = 13

CONTROL_COMMAND_FLAG_MASK: Final[int] = 0x1000
CONTROL_COMMAND_FLAG_OFFSET: Final[int] = 12

SCID_MASK: Final[int] = 0x03FF
SCID_MAX: Final[int] = 0x3FF

VCID_MASK: Final[int] = 0xFC00
VCID_OFFSET: Final[int] = 10
VCID_MAX: Final[int] = 0x3F

FRAME_LENGTH_MASK: Final[int] = 0x03FF
FRAME_LENGTH_MAX: Final[int] = 1024 - 1

FRAME_SEQ_NUM_MASK: Final[int] = 0xFF
FRAME_SEQ_NUM_MAX: Final[int] = 0xFF


class FrameErrorControlField:
    pass


class TcSpaceDataLinkProtocolHeader:
    def __init__(
            self,
            scid: int,
            vcid: int,
            frame_len: int,
            frame_seq_num: int,
            bypass_flag: bool = False,
            control_command_flag: bool = False,
            ccsds_version: int = 0x00,
    ):
        """
        :param scid: Spacecraft ID, should not be larger than 10 bits (0x3FF)
        :param vcid: Virtual Channel ID, should not be larger than 6 bits (0x3F)
        :param frame_len: Contains a length cound C which equals one fewer than the total octets in the transfer frame.
            i.e data_length + header_len (5) + trailer_len (2) - 1
        :param frame_seq_num: frame sequence number, should not be larger than 8 bits (0xFF)
        :param bypass_flag: Bypass Flag, used to control the application of Frame Acceptance Checks
            by the receiver, False by default
        :param command_control_flag: Control Command Flag, used to specify whether the transfer frame is
            conveying control commands (True) or data (False). False by default
        :param ccsds_version: Version number of space data link protocol, default to 0
        :raises ValueError: On invalid parameters

        """
        if scid > SCID_MAX or scid < 0:
            raise ValueError(
                "Invalid scid value, not in range"
                f" 0 < {vcid} <= {SCID_MAX}"
            )
        if vcid > VCID_MAX or vcid < 0:
            raise ValueError(
                "Invalid vcid value, not in range"
                f" 0 < {vcid} <= {VCID_MAX}"
            )
        if frame_len >= FRAME_LENGTH_MAX or frame_len < TC_HEADER_LEN + FEC_LEN:
            raise ValueError(
                "Invalid frame length value, not in range"
                f" {TC_HEADER_LEN + FEC_LEN} < {frame_len} <= {FRAME_LENGTH_MAX}"
            )
        if frame_seq_num > FRAME_SEQ_NUM_MAX or frame_seq_num < 0:
            raise ValueError(
                "Invalid vcid value, not in range"
                f" 0 < {frame_seq_num} <= {FRAME_SEQ_NUM_MAX}"
            )
        self._ccsds_version = ccsds_version
        self._bypass_flag = bypass_flag
        self._control_command_flag = control_command_flag
        self._scid = scid
        self._vcid = vcid
        self._frame_len = frame_len
        self._frame_seq_num = frame_seq_num

    def pack(self) -> bytearray:
        """Serialise raw space data link frame into a bytearray"""
        header = bytearray()
        first_word = (((self.ccsds_version << VERSION_OFFSET) & VERSION_MASK)
                      | ((self.bypass_flag << BYPASS_FLAG_OFFSET) & BYPASS_FLAG_MASK)
                      | ((self.control_command_flag << CONTROL_COMMAND_FLAG_OFFSET) & CONTROL_COMMAND_FLAG_MASK)
                      | (self.scid & SCID_MASK))
        second_word = (((self.vcid << VCID_OFFSET) & VCID_MASK)
                       | ((self.frame_len) & FRAME_LENGTH_MASK))
        seq_num = int.to_bytes(self.frame_seq_num & FRAME_SEQ_NUM_MASK)

        header.extend(struct.pack("!H", first_word))
        header.extend(struct.pack("!H", second_word))
        header.extend(seq_num)
        return header

    @classmethod
    def unpack(cls, data: bytes) -> Self:
        if len(data) < TC_HEADER_LEN:
            raise BytesTooShortError(TC_HEADER_LEN, len(data))

        first_octet = data[0] << 8 | data[1]
        second_octet = data[2] << 8 | data[3]
        version = ((first_octet & VERSION_MASK) >> VERSION_OFFSET)
        bypass_flag = ((first_octet & BYPASS_FLAG_MASK) >> BYPASS_FLAG_OFFSET)
        control_command_flag = (
            (first_octet & CONTROL_COMMAND_FLAG_MASK) >> CONTROL_COMMAND_FLAG_OFFSET)
        scid = (first_octet & SCID_MASK)
        vcid = ((second_octet & VCID_MASK) >> VCID_OFFSET)
        frame_len = (second_octet & FRAME_LENGTH_MASK)
        frame_seq_num = int.from_bytes(data[4])
        return TcSpaceDataLinkProtocolHeader(
            scid=scid,
            vcid=vcid,
            frame_len=frame_len,
            frame_seq_num=frame_seq_num,
            bypass_flag=bool(bypass_flag),
            control_command_flag=bool(control_command_flag),
            ccsds_version=version)

    @property
    def ccsds_version(self) -> int:
        return self._ccsds_version

    @property
    def bypass_flag(self) -> bool:
        return self._bypass_flag

    @property
    def control_command_flag(self) -> bool:
        return self._control_command_flag

    @property
    def scid(self) -> int:
        return self._scid

    @property
    def vcid(self) -> int:
        return self._vcid

    @property
    def frame_len(self) -> int:
        return self._frame_len

    @property
    def frame_seq_num(self) -> int:
        return self._frame_seq_num

    def __repr__(self):
        return (f"{self.__class__.__name__}"
                f"(frame_version={self.ccsds_version!r},"
                f" bypass_flag={self.bypass_flag!r},"
                f" control_command_flag={self.control_command_flag!r},"
                f" scid={self.scid!r}, vcid={self.vcid!r},"
                f" frame_len={self.frame_len!r},"
                f" frame_seq_num={self.frame_seq_num!r})")

    def __eq__(self, other: object):
        if isinstance(other, TcSpaceDataLinkProtocolHeader):
            return self.pack() == other.pack()
        return False
