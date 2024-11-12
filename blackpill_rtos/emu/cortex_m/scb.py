
from emu.mmio.reg import MmioReg
from emu.mmio.peripheral import Peripheral


class Scb(Peripheral):
    REG = {
        "ICSR": (0x04, MmioReg),  # used to trigger pendsv
        "AIRCR": (0x0C, MmioReg),  # used in NVIC_SetPriorityGrouping (we can ignore this?)
        "SHPR1": (0x18, MmioReg),
        "SHPR2": (0x1C, MmioReg),
        "SHPR3": (0x20, MmioReg),
    }

    def __init__(self, uc, base_addr, debug=False):
        super().__init__(uc, base_addr, debug)
        self._pendsv_triggered = False
        self.reg_init()

    def read_cb(self, uc, addr, size, user_data):
        value = self.reg(addr).read_cb(uc, addr, size, user_data)
        self.print(f"SCB MMIO {hex(addr)} read returning value {hex(value)}")
        return value

    def write_cb(self, uc, addr, size, value, user_data):
        self.print(f"SCB MMIO {hex(addr)} written with value {hex(value)}")
        if addr == 0x04 and value & (1 << 28):
            self._pendsv_triggered = True

        self.reg(addr).write_cb(uc, addr, size, value, user_data)

    @property
    def pendsv_triggered(self) -> bool:
        value = self._pendsv_triggered
        self._pendsv_triggered = False
        return value
