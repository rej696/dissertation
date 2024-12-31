class MmioReg:
    def __init__(self, addr, parent):
        self.parent = parent
        self.addr = addr
        self.user_data = None
        self.value = 0

    def read_cb(self, uc, addr, size, user_data):
        return self.value

    def write_cb(self, uc, addr, size, value, user_data):
        self.value = value

    def get_bit(self, n):
        return (self.value >> n) & 0x01

    def set_bit(self, n):
        self.value |= 0x01 << n

    def clr_bit(self, n):
        self.value &= ~(0x01 << n)
