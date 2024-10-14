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

    def __init__(self, uc, base_addr):
        super().__init__(uc, base_addr)
        self.reg_init()
        self.enabled = False
        # self.regs = {
        #     v[0]: v[1](self.base + v[0], self) for v in self.REG.values()
        # }
        # uc.mmio_map(self.base, SYSTICK_MEM_SIZE,
        #             self.read_cb, None, self.write_cb, None)

    def read_cb(self, uc, addr, size, user_data):
        value = self.reg(addr).read_cb(uc, addr, size, user_data)
        print(f"SysTick MMIO {hex(addr)} read returning value {value}")
        return value

    def write_cb(self, uc, addr, size, value, user_data):
        print(f"SysTick MMIO {hex(addr)} written with value {value}")
        self.reg(addr).write_cb(uc, addr, size, value, user_data)
        if self.reg(addr).get_bit(0):
            self.enabled = True
        else:
            self.enabled = False

    def tick(self) -> bool:
        if self.enabled:
            self.reg("VAL").value += 1
            if self.reg("VAL").value >= self.reg("LOAD").value and self.reg("LOAD") != 0:
                # Trigger SysTick Interrupt
                self.reg("VAL").value = 0
                return True
        return False
