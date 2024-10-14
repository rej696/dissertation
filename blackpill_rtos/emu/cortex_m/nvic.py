
from emu.mmio.reg import MmioReg
from emu.mmio.peripheral import Peripheral

class Nvic(Peripheral):
    REG = {
        "TEST": (0, MmioReg),
    }

    def __init__(self, uc, base_addr):
        super().__init__(uc, base_addr)
        self.reg_init()

    def read_cb(self, uc, addr, size, user_data):
        value = self.reg(addr).read_cb(uc, addr, size, user_data)
        print(f"NVIC MMIO{hex(addr)} read returning value {value}")
        return value

    def write_cb(self, uc, addr, size, value, user_data):
        print(f"NVIC MMIO {hex(addr)} written with value {value}")
        self.reg(addr).write_cb(uc, addr, size, value, user_data)
