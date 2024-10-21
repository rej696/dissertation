from unicorn import Uc

class MmioReg:
    def __init__(self, addr, parent):
        self.parent = parent
        self.addr = addr
        self.user_data = None
        self.value = 0

    def read_cb(self, uc: Uc, addr, size, user_data):
        # assert size == 4
        # assert self.addr == addr
        # uc.mem_write(addr, self.value.to_bytes(4, 'little'))
        return self.value

    def write_cb(self, uc: Uc, addr, size, value, user_data):
        # assert self.addr == addr
        # assert size == 4
        self.value = value

    def get_bit(self, n):
        return (self.value >> n) & 0x01

    def set_bit(self, n):
        self.value |= (0x01 << n)

    def clr_bit(self, n):
        self.value &= ~(0x01 << n)
