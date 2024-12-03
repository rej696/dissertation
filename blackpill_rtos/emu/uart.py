from emu.mmio.reg import MmioReg
from emu.mmio.peripheral import Peripheral

from unicorn import Uc

UART1_START_ADDRESS = 0x4001_1000
UART_MEM_SIZE = 0x0000_0400


def byte2str(value):
    if chr(value) == "\n":
        char = r"\n"
    elif chr(value) == "\r":
        char = r"\r"
    else:
        char = chr(value)

    return char


class UartDataReg(MmioReg):
    def __init__(self, addr, parent):
        super().__init__(addr, parent)
        self.read_data = []
        self.write_data = []

    def read_cb(self, uc: Uc, addr, size, user_data):
        return self.read_data.pop(0)

    def write_cb(self, uc: Uc, addr, size, value, user_data):
        self.write_data.append(value)


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

    def __init__(self, uc, base_addr, name, debug=False, terminator=0x0A):
        super().__init__(uc, base_addr, debug)
        self.debug = debug
        self.name = name
        self.ready_to_print = False
        self.terminator = terminator
        self._irq_pending = 0
        self.reg_init()
        uc.mmio_map(self.base, UART_MEM_SIZE, self.read_cb, None, self.write_cb, None)

    def read_cb(self, uc, addr, size, user_data):
        if len(self.reg("DR").read_data) == 0:
            self.reg("SR").clr_bit(5)
        else:
            self.reg("SR").set_bit(5)

        value = self.reg(addr).read_cb(uc, addr, size, user_data)

        if addr != 0:
            if self.REG["DR"][0] == addr:
                char = byte2str(value)

                self.print(
                    f"UART {self.name} MMIO {hex(addr)} read returning value \
                        {hex(value)} ("
                    + char
                    + ")"
                )
                self.reg("SR").clr_bit(5)
            else:
                self.print(f"UART {self.name} MMIO \
                        {hex(addr)} read returning value {hex(value)}")

        return value

    def write_cb(self, uc, addr, size, value, user_data):
        # if write to data register, set sr txe bit
        if self.REG["DR"][0] == addr:
            char = byte2str(value)
            self.print(
                f"UART {self.name} MMIO {hex(addr)} written with value {hex(value)} ("
                + char
                + ")"
            )
            # keep bit 7 of SR always set to indicate that it has been sent
            self.reg("SR").set_bit(7)
        else:
            self.print(f"UART {self.name} MMIO \
                       {hex(addr)} written with value {hex(value)}")

        self.reg(addr).write_cb(uc, addr, size, value, user_data)
        if value == self.terminator:
            self.ready_to_print = True

    def put_byte(self, byte):
        self.reg("DR").read_data.append(byte)
        self._irq_pending += 1

    def put_buf(self, buf):
        for byte in buf:
            self.put_byte(byte)
        self.reg("SR").set_bit(5)

    def get_byte(self):
        return self.reg("DR").write_data.pop(0)

    def print_buf(self):
        if self.reg("SR").get_bit(7):
            self.ready_to_print = False
            string = []
            for _ in range(len(self.reg("DR").write_data)):
                value = self.reg("DR").write_data.pop(0)
                string.append(byte2str(value))
            print(f"Uart {self.name} says: {''.join(string)}")

    def print_buf_hex(self):
        if self.reg("SR").get_bit(7):
            self.ready_to_print = False
            string = []
            for _ in range(len(self.reg("DR").write_data)):
                value = self.reg("DR").write_data.pop(0)
                string.append(value)
            print(f"Uart {self.name} says: {bytearray(string).hex(' ')}")

    @property
    def irq_pending(self):
        if self._irq_pending == 0:
            return False
        self._irq_pending -= 1
        return True
