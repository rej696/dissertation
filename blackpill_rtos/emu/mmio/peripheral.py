
from emu.mmio.reg import MmioReg

class Peripheral:
    REG = {
        "UNKNOWN": (0, MmioReg)
    }

    def __init__(self, uc, base_addr, debug=False):
        self.debug = debug
        self.uc = uc
        self.base = base_addr
        self.regs = dict()

    def reg_init(self):
        self.regs = {
            v[0]: v[1](self.base + v[0], self) for v in self.REG.values()
        }

    def reg(self, id):
        if type(id) == str:
            return self.regs[self.REG[id][0]]
        if type(id) == int:
            return self.regs[id]

    def read_cb(self, uc, addr, size, user_data):
        value = self.reg(addr).read_cb(uc, addr, size, user_data)
        return value

    def write_cb(self, uc, addr, size, value, user_data):
        self.reg(addr).write_cb(uc, addr, size, value, user_data)

    def print(self, string):
        if self.debug:
            print(string)
