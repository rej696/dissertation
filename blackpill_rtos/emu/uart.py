from emu.mmio.reg import MmioReg
from emu.mmio.peripheral import Peripheral

from unicorn import *

UART1_START_ADDRESS = 0x4001_1000
UART_MEM_SIZE = 0x0000_0400


class UartDataReg(MmioReg):
    def __init__(self, addr, parent):
        super().__init__(addr, parent)
        self.read_data = []
        self.write_data = []

    def read_cb(self, uc: Uc, addr, size, user_data):
        return self.read_data

    def write_cb(self, uc: Uc, addr, size, value, user_data):
        # assert self.addr == addr
        # assert size == 4
        self.write_data.append(value)
        self.value = value


class Uart(Peripheral):
    REG = {
        "SR": (0, MmioReg),
        "DR": (4, UartDataReg),
        "BRR": (8, MmioReg),
        "CR1": (12, MmioReg),
        "CR2": (16, MmioReg),
        "CR3": (20, MmioReg),
        "GTPR": (24, MmioReg),
    }

    def __init__(self, uc, base_addr):
        super().__init__(uc, base_addr)
        self.reg_init()
        # self.uc = uc
        # self.base = base_addr
        # self.regs = {
        #     v[0]: v[1](self.base + v[0], self) for v in self.REG.values()
        # }
        uc.mmio_map(self.base, UART_MEM_SIZE, self.read_cb,
                    None, self.write_cb, None)

    # def reg(self, id):
    #     if type(id) == str:
    #         return self.regs[self.REG[id][0]]
    #     if type(id) == int:
    #         return self.regs[id]

    def read_cb(self, uc, addr, size, user_data):
        value = self.reg(addr).read_cb(uc, addr, size, user_data)
        if addr != 0:
            if self.REG["DR"][0] == addr:
                if chr(value) == "\n":
                    char = r"\\\n"
                else:
                    char = chr(value)

                print(f"UART MMIO {hex(addr)} read returning value {
                      hex(value)} (" + char + ")")
            else:
                print(f"UART MMIO {
                      hex(addr)} read returning value {hex(value)}")

        return value

    def write_cb(self, uc, addr, size, value, user_data):
        # if write to data register, set sr txe bit
        if self.REG["DR"][0] == addr:
            if chr(value) == "\n":
                char = r"\\\n"
            else:
                char = chr(value)
            print(f"UART MMIO {hex(addr)} written with value {hex(value)} ("
                  + char + ")")
            self.reg("SR").set_bit(7, 1)
        else:
            print(f"UART MMIO {hex(addr)} written with value {hex(value)}")

        self.reg(addr).write_cb(uc, addr, size, value, user_data)

    def put_byte(self, byte):
        self.dr.value = byte & 0xFF
        self.sr.set_bit(5, 1)
