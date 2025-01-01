from emu.mmio.reg import MmioReg
from emu.mmio.peripheral import Peripheral

SYSTICK_MEM_SIZE = 0x0000_0010


class SysTick(Peripheral):
    REG = {
        "CTRL": (0, MmioReg),
        "LOAD": (4, MmioReg),
        "VAL": (8, MmioReg),
        "CALIB": (12, MmioReg),
    }

    def __init__(self, uc, base_addr, debug=False):
        super().__init__(uc, base_addr, debug)
        self.reg_init()
        self.enabled = False
        self._systick_pending = False

    def read_cb(self, uc, addr, size, user_data):
        value = self.reg(addr).read_cb(uc, addr, size, user_data)
        self.print(f"SysTick MMIO {hex(addr)} read returning value {value}")
        return value

    def write_cb(self, uc, addr, size, value, user_data):
        self.print(f"SysTick MMIO {hex(addr)} written with value {value}")
        self.reg(addr).write_cb(uc, addr, size, value, user_data)
        if self.reg("CTRL") is self.reg(addr):
            if self.reg(addr).get_bit(0):
                self.enabled = True
            else:
                self.enabled = False

    def tick(self):
        if self.enabled:
            self.reg("VAL").value += 1
            if (
                self.reg("VAL").value >= self.reg("LOAD").value
                and self.reg("LOAD") != 0
            ):
                # Trigger SysTick Interrupt
                self._systick_pending = True
                self.reg("VAL").value = 0

    @property
    def systick_pending(self) -> bool:
        value = self._systick_pending
        self._systick_pending = False
        return value
