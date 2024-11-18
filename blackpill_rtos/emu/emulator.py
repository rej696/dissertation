import struct
import random
import sys
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
    UC_HOOK_INTR,
    UC_HOOK_BLOCK,
)
from unicorn.arm_const import (
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_R12,
    UC_ARM_REG_XPSR,
    UC_ARM_REG_PC,
    UC_ARM_REG_LR,
    UC_ARM_REG_SP,
    UC_ARM_REG_MSP,
    UC_ARM_REG_PSP,
    UC_ARM_REG_CONTROL,
    UC_ARM_REG_IPSR,
    UC_ARM_REG_FPSCR,
    UC_ARM_REG_S15,
    UC_ARM_REG_S14,
    UC_ARM_REG_S13,
    UC_ARM_REG_S12,
    UC_ARM_REG_S11,
    UC_ARM_REG_S10,
    UC_ARM_REG_S9,
    UC_ARM_REG_S8,
    UC_ARM_REG_S7,
    UC_ARM_REG_S6,
    UC_ARM_REG_S5,
    UC_ARM_REG_S4,
    UC_ARM_REG_S3,
    UC_ARM_REG_S2,
    UC_ARM_REG_S1,
    UC_ARM_REG_S0,

)

from emu.uart import Uart
from emu.cortex_m.core import CorePeripherals

ARM_CONTEXT_REGISTERS = [
    UC_ARM_REG_XPSR,
    UC_ARM_REG_PC,
    UC_ARM_REG_LR,
    UC_ARM_REG_R12,
    UC_ARM_REG_R3,
    UC_ARM_REG_R2,
    UC_ARM_REG_R1,
    UC_ARM_REG_R0,
]
ARM_FLOAT_CONTEXT_REGISTERS = [
    UC_ARM_REG_FPSCR,
    UC_ARM_REG_S15,
    UC_ARM_REG_S14,
    UC_ARM_REG_S13,
    UC_ARM_REG_S12,
    UC_ARM_REG_S11,
    UC_ARM_REG_S10,
    UC_ARM_REG_S9,
    UC_ARM_REG_S8,
    UC_ARM_REG_S7,
    UC_ARM_REG_S6,
    UC_ARM_REG_S5,
    UC_ARM_REG_S4,
    UC_ARM_REG_S3,
    UC_ARM_REG_S2,
    UC_ARM_REG_S1,
    UC_ARM_REG_S0,
]


FLASH_START_ADDRESS = 0x0800_0000
FLASH_SIZE = 0x0008_0000  # 512k

SRAM_START_ADDRESS = 0x2000_0000
SRAM_SIZE = 0x0002_0000  # 128k

GPIO_START_ADDRESS = 0x4002_0000
GPIO_SIZE = 0x0000_1400

RCC_START_ADDRESS = 0x4002_3800
RCC_SIZE = 0x0000_0400

UART1_START_ADDRESS = 0x4001_1000
UART2_START_ADDRESS = 0x4000_4400
UART_SIZE = 0x0000_0400

SYSTICK_START_ADDRESS = 0xE000_E010

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
    def __init__(self, firmware_path, base_addr, debug=False) -> None:
        self.debug = debug
        self.input_string = [ord(c) for c in "Smelly Boy!\r\n"]
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN)
        self.cs = Cs(
            CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS | CS_MODE_LITTLE_ENDIAN
        )
        self.cs.detail = True
        self.base_addr = base_addr
        self.interrupt_enabled = True
        self.interrupt_context = False

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
        # TODO Convert into MMIO peripheral
        self.uc.mem_map(GPIO_START_ADDRESS, GPIO_SIZE)
        # self.uc.mem_map(UART1_START_ADDRESS, UART1_SIZE)
        self.uc.mem_map(RCC_START_ADDRESS, RCC_SIZE)
        # self.uc.mem_map(CORTEX_M_INT_PERIPH_START_ADDR,
        #                 CORTEX_M_INT_PERIPH_SIZE)

        # Special Value for EXEC_RETURN
        self.uc.mem_map(0xFFFFF000, 0x1000)

        # TODO setup uc hooks
        self.print_instr = False
        self.uc.hook_add(UC_HOOK_CODE, self.uc_code_cb)
        # self.uc.hook_add(UC_HOOK_BLOCK, self.uc_mem_block_cb,
        #                  begin=0xFFFFF000, end=0xFFFFFFFF)

        self.cortex_m = CorePeripherals(self.uc)
        self.cortex_m.scb.debug = False
        self.uart1 = Uart(self.uc, UART1_START_ADDRESS, 1)
        self.uart2 = Uart(self.uc, UART2_START_ADDRESS, 2)
        self.uart2.debug = False


    def save_context(self, uc, spsel, fpca):
        if self.debug:
            print("Saving Context (old)")
            self.dump_reg()
        sp_reg = UC_ARM_REG_MSP
        if spsel:
            sp_reg = UC_ARM_REG_PSP

        sp = uc.reg_read(sp_reg)
        if fpca:
            for reg in ARM_FLOAT_CONTEXT_REGISTERS:
                val = uc.reg_read(reg)
                sp -= 4
                uc.mem_write(sp, val.to_bytes(4, 'little'))

        for reg in ARM_CONTEXT_REGISTERS:
            val = uc.reg_read(reg)
            sp -= 4
            uc.mem_write(sp, val.to_bytes(4, 'little'))

        uc.reg_write(UC_ARM_REG_SP, sp)

    def restore_context(self, uc, spsel, fpca):
        if self.debug:
            print("Previous Context:")
            self.dump_reg()
        sp_reg = UC_ARM_REG_MSP
        if spsel:
            sp_reg = UC_ARM_REG_PSP

        sp = uc.reg_read(sp_reg)
        for reg in ARM_CONTEXT_REGISTERS[::-1]:
            data = uc.mem_read(sp, 4)
            val = struct.unpack('<I', data)[0]
            sp += 4
            uc.reg_write(reg, val)
        if fpca:
            for reg in ARM_FLOAT_CONTEXT_REGISTERS[::-1]:
                data = uc.mem_read(sp, 4)
                val = struct.unpack('<I', data)[0]
                sp += 4
                uc.reg_write(reg, val)
                val = uc.reg_read(reg)

        uc.reg_write(UC_ARM_REG_SP, sp)
        if self.debug:
            print("Restored Context:")
            self.dump_reg()

    def handle_interrupt(self, uc, isr):
        # TODO make this better?

        def isr_handler():
            isr_addr = self.vector_table[isr]
            if self.debug:
                print(f"Entering ISR {isr}")
            control = uc.reg_read(UC_ARM_REG_CONTROL)
            spsel = bool(control & 0b10)  # which stack pointer is active?
            fpca = bool(control & 0b100)  # floating point context?
            self.save_context(uc, spsel, fpca)
            pc = isr_addr
            lr = 0xffffffe9
            if spsel:
                lr |= 0b100
            if not fpca:
                lr |= 0b10000
            uc.reg_write(UC_ARM_REG_LR, lr)
            uc.reg_write(UC_ARM_REG_IPSR, 15)
            uc.reg_write(UC_ARM_REG_PC, pc)
            self.interrupt_context = True
            if self.debug:
                print(f"Entering ISR @ {hex(isr_addr)}")
                self.dump_reg()
            self.uc.emu_start(
                isr_addr,
                0xFFFFFFF8)

        self.trampoline_handlers.append(isr_handler)
        self.trampoline_handlers.append(self.return_from_interrupt)
        self.uc.emu_stop()

    def return_from_interrupt(self):
        lr = self.uc.reg_read(UC_ARM_REG_LR)
        irq_num = self.uc.reg_read(UC_ARM_REG_IPSR)
        if not self.interrupt_enabled or not self.interrupt_context:
            print("ERROR")
            return
        if ((lr & 0xffffff00) == 0xffffff00):
            spsel = bool(lr & 0b100)
            fpca = not bool(lr & 0b10000)
            self.restore_context(self.uc, spsel, fpca)
            pc = self.uc.reg_read(UC_ARM_REG_PC)
            sp = self.uc.reg_read(UC_ARM_REG_SP)
            control = 0
            if spsel:
                control |= 0b10
            if fpca:
                control |= 0b100
            self.uc.reg_write(UC_ARM_REG_CONTROL, control)
        else:
            control = self.uc.reg_read(UC_ARM_REG_CONTROL)
            spsel = bool(control & 0b10)
            fcpa = bool(control & 0b100)
            pc = self.uc.reg_read(UC_ARM_REG_PC)
            sp = self.uc.reg_read(UC_ARM_REG_SP)
            self.restore_context(self.uc, spsel, fcpa)
            pc = self.uc.reg_read(UC_ARM_REG_PC)
            sp = self.uc.reg_read(UC_ARM_REG_SP)

        self.interrupt_context = False
        if self.debug:
            print(f"Returning from ISR to PC {hex(pc)}, SP {hex(sp)}")
        self.uc.emu_start(
            pc + 1,
            self.fw_size + self.base_addr,
        )

    def uc_mem_block_cb(self, uc, address, size, data):
        irq_num = uc.reg_read(UC_ARM_REG_IPSR)
        self.return_from_interrupt(uc)

    def uc_code_cb(self, uc: Uc, addr, size, user_data):
        # This hook just prints the instruction being executed
        print_instr = True
        code = uc.mem_read(addr, size)

        # handle cpsid and cpsie instructions
        if code == bytearray((0x72, 0xb6)):
            self.interrupt_enabled = False
        if code == bytearray((0x62, 0xb6)):
            self.interrupt_enabled = True

        # handle interrupts
        # TODO not interrupt context blocks interrupts from being called inside other interrupts
        # (so systick won't tick while interrupts are in progress)
        # This doesn't work because the trampoline handlers exit the interrupt context before pre-empting the interrupts
        # maybe get handle interrupt to insert isr handlers infront of the next trampoline handler?
        if self.interrupt_enabled and not self.interrupt_context:
            if self.cortex_m.systick.tick():
                self.handle_interrupt(uc, "systick_handler")

            elif self.cortex_m.scb.pendsv_triggered:
                self.handle_interrupt(uc, "pendsv_handler")

        if self.uart2.ready_to_print:
            def uart2_trampoline_handler():
                self.uart2.print_buf()
                pc = self.uc.reg_read(UC_ARM_REG_PC)
                self.uc.emu_start(
                    pc + 1,
                    self.fw_size + self.base_addr,
                )
            self.trampoline_handlers.append(uart2_trampoline_handler)
            self.uc.emu_stop()

        # check for DBC exception being raised
        if addr in range(0x8000284, 0x800029d):
            print("DBC_Exception")
            raise Exception("DBC_Exception")

        print_instr = False
        if print_instr and (addr not in [0x80006d2, 0x80003de, 0x80006d6] or addr not in [0x8000856, 0x8000858, 0x8000888, 0x800088c]):  # idle loop
            for instruction in self.cs.disasm(code, addr, 1):
                print(f"{hex(addr)}\t {instruction.mnemonic} {
                      instruction.op_str}")

    def dump_reg(self):
        print("\tRegister Dump:")
        print(f"\t\tPC: {hex(self.uc.reg_read(UC_ARM_REG_PC))}")
        print(f"\t\tLR: {hex(self.uc.reg_read(UC_ARM_REG_LR))}")
        print(f"\t\tSP: {hex(self.uc.reg_read(UC_ARM_REG_SP))}")
        print(f"\t\tR0: {hex(self.uc.reg_read(UC_ARM_REG_R0))}")
        print(f"\t\tR1: {hex(self.uc.reg_read(UC_ARM_REG_R1))}")
        print(f"\t\tR2: {hex(self.uc.reg_read(UC_ARM_REG_R2))}")
        print(f"\t\tR3: {hex(self.uc.reg_read(UC_ARM_REG_R3))}")
        print(f"\t\tR12: {hex(self.uc.reg_read(UC_ARM_REG_R12))}")

    def reset_handler(self):
        self.uc.emu_start(
            self.vector_table["reset_handler"],
            self.fw_size + self.base_addr,
            # 200_000 * UC_MILISECOND_SCALE,
            # 20000 * UC_MILISECOND_SCALE,
            # 0,
        )

    def start(self):
        self.trampoline_handlers = [self.reset_handler]
        self.uc.reg_write(
            UC_ARM_REG_MSP, self.vector_table["initial_stack_pointer"])
        try:
            while True:
                handler = self.trampoline_handlers.pop(0)
                if self.debug:
                    print("Trampoline Handler:")
                    self.dump_reg()
                handler()

        except KeyboardInterrupt:
            sys.exit(0)
        except Exception as e:
            print("Exception:")
            self.dump_reg()
            print(e)
