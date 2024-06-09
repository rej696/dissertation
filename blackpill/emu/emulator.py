import struct
from collections import OrderedDict

from capstone import (
    Cs,
    CS_ARCH_ARM,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_MCLASS,
    CS_MODE_THUMB,
)

# from capstone.arm_const import
from unicorn import (
    Uc,
    UC_ARCH_ARM,
    UC_MODE_LITTLE_ENDIAN,
    UC_MILISECOND_SCALE,
    UC_HOOK_CODE,
)
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_MSP

FLASH_START_ADDRESS = 0x0800_0000
FLASH_SIZE = 0x0008_0000  # 512k

SRAM_START_ADDRESS = 0x2000_0000
SRAM_SIZE = 0x0002_0000  # 128k

GPIO_START_ADDRESS = 0x4002_0000
GPIO_SIZE = 0x0000_1400

RCC_START_ADDRESS = 0x4002_3800
RCC_SIZE = 0x0000_0400

UART1_START_ADDRESS = 0x4001_1000
UART1_SIZE = 0x0000_0400

CORTEX_M_INT_PERIPH_START_ADDR = 0xE000_0000
CORTEX_M_INT_PERIPH_SIZE = 0x0010_0000


class VectorTable(OrderedDict):
    __vtable_entries = {
        "initial_stack_pointer": 0,
        "reset_handler": 4,
        "nmi_handler": 8,
        "hardfault_handler": 12,
        "memmanage_handler": 16,
        "busfault_handler": 20,
        "usagefault_handler": 24,
        "reserved1": 28,
        "reserved2": 32,
        "reserved3": 36,
        "reserved4": 40,
        "svcall_handler": 44,
        "reserved5": 48,  # reserved for debug
        "reserved6": 52,
        "pendsv_handler": 56,
        "systick_handler": 60,
        # "irq_handler": 64, # No Custom IRQ's included at the moment
    }

    def __repr__(self) -> str:
        return "".join(k + ":" + hex(v) + "\n" for k, v in self.items())

    @staticmethod
    def parse(bin):
        return VectorTable(
            {
                name: struct.unpack("<I", bin[offset: offset + 4])[0]
                for name, offset in VectorTable.__vtable_entries.items()
            }
        )


def get_aligned_size(length):
    if length % 1024 == 0:
        return length
    return 1024 * (length // 1024) + 1024


def skip_instruction(uc, addr, size):
    # increment program counter by size
    uc.reg_write(UC_ARM_REG_PC, (addr + size) | 1)


class Emulator:
    def __init__(self, firmware_path, base_addr) -> None:
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN)
        self.cs = Cs(
            CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS | CS_MODE_LITTLE_ENDIAN
        )
        self.cs.detail = True
        self.base_addr = base_addr

        # TODO Load registers from an SVD file?

        with open(firmware_path, "rb") as f:
            fw = f.read()
            self.fw_size = len(fw)
            self.vector_table = VectorTable.parse(fw)
            print(f"[*] loaded vector table:\n{self.vector_table}")

            size = get_aligned_size(self.fw_size)
            self.uc.mem_map(self.base_addr, size)
            self.uc.mem_write(self.base_addr, fw)

        # Setup memory map and map peripherals
        self.uc.mem_map(SRAM_START_ADDRESS, SRAM_SIZE)
        self.uc.mem_map(GPIO_START_ADDRESS, GPIO_SIZE)
        self.uc.mem_map(UART1_START_ADDRESS, UART1_SIZE)
        self.uc.mem_map(RCC_START_ADDRESS, RCC_SIZE)
        self.uc.mem_map(CORTEX_M_INT_PERIPH_START_ADDR,
                        CORTEX_M_INT_PERIPH_SIZE)

        # TODO setup uc hooks
        self.uc.hook_add(UC_HOOK_CODE, self.uc_code_cb)

    def uc_code_cb(self, uc, addr, size, user_data):
        # This hook just prints the instruction being executed
        code = uc.mem_read(addr, size)
        for instruction in self.cs.disasm(code, addr, 1):
            print(f"{hex(addr)}\t {instruction.mnemonic} {instruction.op_str}")

    def start(self):
        self.uc.reg_write(
            UC_ARM_REG_MSP, self.vector_table["initial_stack_pointer"])
        try:
            self.uc.emu_start(
                self.vector_table["reset_handler"],
                self.fw_size + self.base_addr,
                5 * UC_MILISECOND_SCALE,
                0,
            )
        except Exception as e:
            print(e)
