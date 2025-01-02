from emu.mmio.peripheral import Peripheral, PeripheralNotEmulatedException
from emu.cortex_m.systick import SysTick
from emu.cortex_m.scb import Scb
from emu.cortex_m.nvic import Nvic

CORE_PERIPHERALS_START_ADDRESS = 0xE000_E000
CORE_PERIPHERALS_MEM_SIZE = 0x0000_1000


class CorePeripherals:
    PERIPH = {
        "ACTLR": ((0x0008, 0x0010), Peripheral),
        "SYSTICK": ((0x0010, 0x0020), SysTick),
        "NVIC": ((0x0100, 0x0D00), Nvic),
        "SCB": ((0x0D00, 0x0D40), Scb),
    }

    def __init__(self, uc):
        self.uc = uc
        self.base = CORE_PERIPHERALS_START_ADDRESS
        self.periphs = {
            v[0]: v[1](self.uc, self.base + v[0][0]) for v in self.PERIPH.values()
        }
        self.systick = self.periphs[self.PERIPH["SYSTICK"][0]]
        self.scb = self.periphs[self.PERIPH["SCB"][0]]

        uc.mmio_map(
            self.base,
            CORE_PERIPHERALS_MEM_SIZE,
            self.read_cb,
            None,
            self.write_cb,
            None,
        )

    def periph(self, addr):
        for k in self.periphs.keys():
            if addr in range(*k):
                return self.periphs[k], addr - k[0]

        raise PeripheralNotEmulatedException(addr)

    def read_cb(self, uc, addr, size, user_data):
        p, offset = self.periph(addr)
        value = p.read_cb(uc, offset, size, user_data)
        return value

    def write_cb(self, uc, addr, size, value, user_data):
        p, offset = self.periph(addr)
        p.write_cb(uc, offset, size, value, user_data)
