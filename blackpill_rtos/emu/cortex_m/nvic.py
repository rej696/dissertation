from emu.mmio.reg import MmioReg
from emu.mmio.peripheral import Peripheral


class Nvic(Peripheral):
    REG = {
        "ISER0": (0, MmioReg),  # (not used)
        "ISER1": (0x4, MmioReg),  # For enabling the usart 1 and usart 2 interrupts
        "ISER2": (0x8, MmioReg),  # For enabling the usart 6 interrupt
        "IP37": (0x300 + 37, MmioReg),  # IP (interrupt priority) register for usart 1
        "IP38": (0x300 + 38, MmioReg),  # IP (interrupt priority) register for usart 2
        "IP71": (0x300 + 71, MmioReg),  # IP (interrupt priority) register for usart 6
    }

    def __init__(self, uc, base_addr):
        super().__init__(uc, base_addr)
        self.reg_init()

    def read_cb(self, uc, addr, size, user_data):
        value = self.reg(addr).read_cb(uc, addr, size, user_data)
        print(f"NVIC MMIO{hex(addr)} read returning value {bin(value)}")
        return value

    def write_cb(self, uc, addr, size, value, user_data):
        print(f"NVIC MMIO {hex(addr)} written with value {bin(value)}")
        self.reg(addr).write_cb(uc, addr, size, value, user_data)
