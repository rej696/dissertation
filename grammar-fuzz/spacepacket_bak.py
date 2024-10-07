

def take(iter, n):
    for _, x in zip(range(n), iter):
        yield x

TM=0
TC=1

VALID_APID = {-1, 2, 3}

SEQ_FLAG = {
        "continuation": 0b00,
        "first-segment": 0b01,
        "last-segment": 0b10,
        "unsegmented":0b11
        }


class SpacePacketBuilder:

    def __init__(self, version=0, _type=TC, seq_flag=0b11):
        self.version = version
        self._type = _type
        self.seq_flag = seq_flag
        self.seq_num = 0


    def __next__(self, _bytes):
        # take in a stream of bytes, and read of needed bits
        apid = take(_bytes, len(VALID_APID))

        yield SpacePacket(self.version, self._type, self.seq_num, payload)
        self.seq_num += 1


class SpacePacket:
    def __init__(self, version, _type, sec_hdr, apid, seq_flag, seq_count, bitstream):
        self.version = version
        self._type = _type
        self.sec_hdr = sec_hdr
        self.apid = apid
        self.seq_flag = seq_flag
        self.seq_count = seq_count


    @staticmethod
    def from_stream(stream):
        _bytes = list(take(stream, 5))
        sec_hdr = (_bytes[0] >> 8) & 0x1
        apid = (_bytes[0] >> 7) & 0x1
        return SpacePacket(sec_hdr=sec_hdr, apid=apid)


    def to_bytes():
        stream
        stream[0] = struct.pack(





def spacepacket_stream(input):
    """Take a stream of random input data and output valid spacepackets byte by byte"""
    sp_builder = SpacePacketBuilder()

    for byte in sp.to_bytes():
        yield byte


if __name__ == "__main__":
    deadbeef_gen = (x for x in b"\xDE\xAD\xBE\xEF")
    for byte in spacepacket_stream(deadbeef_gen):
        print(hex(byte), end="")




