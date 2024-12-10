import struct
import os
import signal
from collections import OrderedDict

from capstone import (
    Cs,
    CS_ARCH_ARM,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_MCLASS,
    CS_MODE_THUMB,
)

from unicornafl import (
    Uc,
    UcError,
    UC_ARCH_ARM,
    UC_MODE_LITTLE_ENDIAN,
    UC_HOOK_CODE,
    UC_ERR_OK,
    UC_ERR_EXCEPTION,
    UC_ERR_INSN_INVALID,
    UC_ERR_READ_UNMAPPED,
    UC_ERR_READ_PROT,
    UC_ERR_READ_UNALIGNED,
    UC_ERR_WRITE_UNMAPPED,
    UC_ERR_WRITE_PROT,
    UC_ERR_WRITE_UNALIGNED,
    UC_ERR_FETCH_UNMAPPED,
    UC_ERR_FETCH_PROT,
    UC_ERR_FETCH_UNALIGNED,
)
from unicorn.arm_const import (
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_R4,
    UC_ARM_REG_R5,
    UC_ARM_REG_R6,
    UC_ARM_REG_R7,
    UC_ARM_REG_R8,
    UC_ARM_REG_R9,
    UC_ARM_REG_R10,
    UC_ARM_REG_R11,
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
from emu.spacepacket_handler import SpacepacketHandler, OutOfPacketsException

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


class EmulatorException(Exception):
    errno = None


class DbcException(Exception):
    errno = None
    pass


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
        # STM32 Custom IRQ's
        "uart1_handler": 212,
        "uart2_handler": 216,
    }

    def __repr__(self) -> str:
        return "".join(k + ":" + hex(v) + "\n" for k, v in self.items())

    @staticmethod
    def parse(bin):
        return VectorTable(
            {
                name: struct.unpack("<I", bin[offset : offset + 4])[0]
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
    def __init__(
        self,
        firmware_path,
        base_addr,
        debug=False,
        dbc_addr_range=range(0x800028D, 0x80002A9),
        coverage=False,
    ) -> None:
        self.debug = debug
        self.dbc_addr_range = dbc_addr_range
        self.cov = set() if coverage else None
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN)
        self.cs = Cs(
            CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS | CS_MODE_LITTLE_ENDIAN
        )
        self.cs.detail = True
        self.base_addr = base_addr
        self.interrupt_enabled = True
        self.spp_handler = SpacepacketHandler()
        self.packet = None
        self.interrupt_context = ["None"]

        with open(firmware_path, "rb") as f:
            fw = f.read()
            self.fw_size = len(fw)
            self.vector_table = VectorTable.parse(fw)
            self.print(f"[*] loaded vector table:\n{self.vector_table}")

            size = get_aligned_size(self.fw_size)
            self.uc.mem_map(self.base_addr, size)
            self.uc.mem_write(self.base_addr, fw)

        # Setup memory map and map peripherals
        self.uc.mem_map(SRAM_START_ADDRESS, SRAM_SIZE)
        self.uc.mem_map(GPIO_START_ADDRESS, GPIO_SIZE)
        self.uc.mem_map(RCC_START_ADDRESS, RCC_SIZE)

        # Special Value for EXEC_RETURN
        self.uc.mem_map(0xFFFFF000, 0x1000)
        # Enable/Disable Exits
        self.uc.ctl_exits_enabled(True)
        self.uc.ctl_set_exits([0xFFFFFFF8])

        # Setup Code Hook
        self.uc.hook_add(UC_HOOK_CODE, self.uc_code_cb)

        # Setup Peripheral Models
        self.cortex_m = CorePeripherals(self.uc)
        self.uart1 = Uart(self.uc, UART1_START_ADDRESS, 1, terminator=0xC0)  # KISS_FEND
        self.uart2 = Uart(self.uc, UART2_START_ADDRESS, 2, terminator=0x0A)  # '\n'
        self.cortex_m.scb.debug = False
        self.uart1.debug = False
        self.uart2.debug = False

    def uc_debug_read_cb(self, uc, access, addr, size, value, user_data):
        self.print(f"Reading memory @ {hex(addr)}[{hex(size)}]")
        self.print(f"{access}, {addr}, {size}, {value}")
        self.dump_mem(addr, size)

    def uc_debug_write_cb(self, uc, access, addr, size, value, user_data):
        self.print(f"Writing memory @ {hex(addr)}[{hex(size)}]")
        self.print(f"{access}, {addr}, {size}, {value}")
        self.dump_mem(addr, size)

    def save_context(self, uc, spsel, fpca):
        if self.debug:
            self.print("Saving Context (old)")
            self.dump_reg()
        sp_reg = UC_ARM_REG_MSP
        if spsel:
            sp_reg = UC_ARM_REG_PSP

        sp = uc.reg_read(sp_reg)
        if fpca:
            for reg in ARM_FLOAT_CONTEXT_REGISTERS:
                val = uc.reg_read(reg)
                sp -= 4
                uc.mem_write(sp, val.to_bytes(4, "little"))

        for reg in ARM_CONTEXT_REGISTERS:
            val = uc.reg_read(reg)
            sp -= 4
            uc.mem_write(sp, val.to_bytes(4, "little"))

        uc.reg_write(UC_ARM_REG_SP, sp)

    def restore_context(self, uc, spsel, fpca):
        if self.debug:
            self.print("Previous Context:")
            self.dump_reg()
        sp_reg = UC_ARM_REG_MSP
        if spsel:
            sp_reg = UC_ARM_REG_PSP

        sp = uc.reg_read(sp_reg)
        for reg in ARM_CONTEXT_REGISTERS[::-1]:
            data = uc.mem_read(sp, 4)
            val = struct.unpack("<I", data)[0]
            sp += 4
            uc.reg_write(reg, val)
        if fpca:
            for reg in ARM_FLOAT_CONTEXT_REGISTERS[::-1]:
                data = uc.mem_read(sp, 4)
                val = struct.unpack("<I", data)[0]
                sp += 4
                uc.reg_write(reg, val)
                val = uc.reg_read(reg)

        uc.reg_write(UC_ARM_REG_SP, sp)
        if self.debug:
            self.print("Restored Context:")
            self.dump_reg()

    def handle_interrupt(self, uc, isr):
        def isr_handler():
            isr_addr = self.vector_table[isr]
            if self.debug:
                self.print(f"Entering ISR {isr}")
            control = uc.reg_read(UC_ARM_REG_CONTROL)
            spsel = bool(control & 0b10)  # which stack pointer is active?
            fpca = bool(control & 0b100)  # floating point context?
            self.save_context(uc, spsel, fpca)
            pc = isr_addr
            lr = 0xFFFFFFE9
            if spsel:
                lr |= 0b100
            if not fpca:
                lr |= 0b10000
            uc.reg_write(UC_ARM_REG_LR, lr)
            uc.reg_write(UC_ARM_REG_IPSR, 15)
            uc.reg_write(UC_ARM_REG_PC, pc)
            self.interrupt_context.append(isr)
            if self.debug:
                self.print(
                    f"Entering ISR @ {hex(isr_addr)}, "
                    + f"IRQ stack {self.interrupt_context}"
                )
                self.dump_reg()
            self.uc.emu_start(isr_addr, 0xFFFFFFF8)

        self.trampoline_handlers.insert(0, self.return_from_interrupt)
        self.trampoline_handlers.insert(0, isr_handler)
        self.uc.emu_stop()

    def return_from_interrupt(self):
        lr = self.uc.reg_read(UC_ARM_REG_LR)
        irq_num = self.uc.reg_read(UC_ARM_REG_IPSR)
        interrupt_context = self.interrupt_context.pop()
        if not self.interrupt_enabled:
            self.print(
                "ERROR: attempting to return from interrupt while interrupts are disabled?"
            )
            return

        if (lr & 0xFFFFFF00) == 0xFFFFFF00:
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

        if self.debug:
            self.print(
                f"Returning from ISR ({irq_num}, {interrupt_context}) to PC {hex(pc)}, SP {hex(sp)}"
            )
        self.uc.emu_start(
            pc + 1,
            self.fw_size + self.base_addr,
        )

    def uc_code_cb(self, uc: Uc, addr, size, user_data):
        if self.cov is not None and addr not in self.cov:
            self.cov.add(addr)

        code = uc.mem_read(addr, size)
        # handle cpsid and cpsie instructions
        if code == bytearray((0x72, 0xB6)):
            self.interrupt_enabled = False
        if code == bytearray((0x62, 0xB6)):
            self.interrupt_enabled = True

        # Tick systick peripheral
        self.cortex_m.systick.tick()

        # handle interrupts
        if self.interrupt_enabled:
            if (
                not (
                    self.interrupt_context[-1] == "systick_handler"
                    and len(self.interrupt_context) > 2
                )
            ) and self.cortex_m.systick.systick_pending:
                # only trigger send spacepacket on systick
                self.packet = next(self.packets)
                self.handle_interrupt(uc, "systick_handler")

            elif (
                self.interrupt_context[-1] != "pendsv_handler"
                and self.cortex_m.scb.pendsv_pending
            ):
                self.handle_interrupt(uc, "pendsv_handler")

            elif (
                self.interrupt_context[-1] != "uart1_handler" and self.uart1.irq_pending
            ):
                self.handle_interrupt(uc, "uart1_handler")

        if self.packet:
            self.print(f"Uart 1 sent: {self.packet.hex(' ')}")
            self.uart1.put_buf(self.packet)
            self.packet = None

        if self.uart2.ready_to_print:

            def uart2_trampoline_handler():
                if string := self.uart2.print_buf():
                    self.print(string)
                pc = self.uc.reg_read(UC_ARM_REG_PC)
                self.uc.emu_start(
                    pc + 1,
                    self.fw_size + self.base_addr,
                )

            self.trampoline_handlers.insert(0, uart2_trampoline_handler)
            self.uc.emu_stop()

        if self.uart1.ready_to_print:

            def uart1_trampoline_handler():
                if string := self.uart1.print_buf_hex():
                    self.print(string)
                pc = self.uc.reg_read(UC_ARM_REG_PC)
                self.uc.emu_start(
                    pc + 1,
                    self.fw_size + self.base_addr,
                )

            self.trampoline_handlers.insert(0, uart1_trampoline_handler)
            self.uc.emu_stop()

        # check for DBC exception being raised
        if addr in self.dbc_addr_range:
            raise DbcException("DBC_Exception triggered")

        # print instruction
        if self.debug:
            for instruction in self.cs.disasm(code, addr, 1):
                self.print(
                    f"{hex(addr)}\t {instruction.mnemonic}" + f" {instruction.op_str}"
                )

    def dump_mem(self, addr, size):
        def chunks(line, n):
            for i in range(0, len(line), n):
                yield line[i : i + n]

        self.print(f"\tMemory: @ {hex(addr)}")
        mem = self.uc.mem_read(addr, size)

        for row in chunks(mem, 16):
            half_rows = tuple(chunks(row, 8))
            if len(half_rows) < 2:
                self.print(f"\t\t{hex(addr)}: {half_rows[0].hex(' ')}")
            else:
                self.print(
                    f"\t\t{hex(addr)}: {half_rows[0].hex(' ')}"
                    + f"    {half_rows[1].hex(' ')}"
                )
            addr += 16

    def dump_reg(self):
        self.print("\tRegister Dump:")
        self.print(f"\t\tPC: {hex(self.uc.reg_read(UC_ARM_REG_PC))}")
        self.print(f"\t\tLR: {hex(self.uc.reg_read(UC_ARM_REG_LR))}")
        self.print(f"\t\tSP: {hex(self.uc.reg_read(UC_ARM_REG_SP))}")
        self.print(f"\t\tR0: {hex(self.uc.reg_read(UC_ARM_REG_R0))}")
        self.print(f"\t\tR1: {hex(self.uc.reg_read(UC_ARM_REG_R1))}")
        self.print(f"\t\tR2: {hex(self.uc.reg_read(UC_ARM_REG_R2))}")
        self.print(f"\t\tR3: {hex(self.uc.reg_read(UC_ARM_REG_R3))}")
        self.print(f"\t\tR4: {hex(self.uc.reg_read(UC_ARM_REG_R4))}")
        self.print(f"\t\tR5: {hex(self.uc.reg_read(UC_ARM_REG_R5))}")
        self.print(f"\t\tR6: {hex(self.uc.reg_read(UC_ARM_REG_R6))}")
        self.print(f"\t\tR7: {hex(self.uc.reg_read(UC_ARM_REG_R7))}")
        self.print(f"\t\tR8: {hex(self.uc.reg_read(UC_ARM_REG_R8))}")
        self.print(f"\t\tR9: {hex(self.uc.reg_read(UC_ARM_REG_R9))}")
        self.print(f"\t\tR10: {hex(self.uc.reg_read(UC_ARM_REG_R10))}")
        self.print(f"\t\tR11: {hex(self.uc.reg_read(UC_ARM_REG_R11))}")
        self.print(f"\t\tR12: {hex(self.uc.reg_read(UC_ARM_REG_R12))}")
        sp = self.uc.reg_read(UC_ARM_REG_SP)
        self.print(f"\tStack: @ {hex(sp)}")
        self.dump_mem(sp - 0x40, 0x40)

    def reset_handler(self):
        self.uc.emu_start(
            self.vector_table["reset_handler"],
            self.fw_size + self.base_addr,
        )

    def start(self):
        self.packets = self.spp_handler.packet_generator()
        self.trampoline_handlers = [self.reset_handler]
        self.uc.reg_write(UC_ARM_REG_MSP, self.vector_table["initial_stack_pointer"])
        try:
            while True:
                handler = self.trampoline_handlers.pop(0)
                if self.debug:
                    self.print("Trampoline Handler:")
                    self.dump_reg()
                handler()
        except UcError as e:
            self.print(f"Exception {e}:")
            self.dump_reg()
            force_crash(e)
        except EmulatorException as e:
            self.print(f"Emulator Exception {e}:")
            self.dump_reg()
            force_crash(e)
        except DbcException as e:
            self.print(f"DBC Exception {e}:")
            self.dump_reg()
            force_crash(e)
        except OutOfPacketsException as e:
            self.print(f"OutOfPacketsException: {e}")
        except Exception as e:
            self.print(f"Unhandled Exception {e}:")
            self.dump_reg()
            raise e

    def print(self, string):
        if self.cov is None:
            print(">>>" + string)


def fuzz_start(uc, self):
    self.packets = self.spp_handler.packet_generator()
    self.uc = uc
    self.trampoline_handlers = [self.reset_handler]
    self.uc.reg_write(UC_ARM_REG_MSP, self.vector_table["initial_stack_pointer"])
    try:
        while True:
            handler = self.trampoline_handlers.pop(0)
            if self.debug:
                self.print("Trampoline Handler:")
                self.dump_reg()
            handler()
    except UcError as e:
        self.print(f"Exception {e}:")
        self.dump_reg()
        return e.errno
    # handle execeptions for afl correctly (i.e. which are crashes and which just the end of execution)
    except EmulatorException as e:
        self.print(f"Emulator Exception {e}:")
        self.dump_reg()
        return UC_ERR_EXCEPTION
    except DbcException as e:
        self.print(f"DBC Exception {e}:")
        self.dump_reg()
        return UC_ERR_EXCEPTION
    except OutOfPacketsException as e:
        self.print(f"OutOfPacketsException: {e}")
        return UC_ERR_OK
    except Exception as e:
        print(f"Unhandled Exception {e}:")
        self.dump_reg()
        return UC_ERR_EXCEPTION

    return UC_ERR_OK


def force_crash(uc_error):
    mem_errors = [
        UC_ERR_READ_UNMAPPED,
        UC_ERR_READ_PROT,
        UC_ERR_READ_UNALIGNED,
        UC_ERR_WRITE_UNMAPPED,
        UC_ERR_WRITE_PROT,
        UC_ERR_WRITE_UNALIGNED,
        UC_ERR_FETCH_UNMAPPED,
        UC_ERR_FETCH_PROT,
        UC_ERR_FETCH_UNALIGNED,
    ]
    if uc_error.errno in mem_errors:
        os.kill(os.getpid(), signal.SIGSEGV)
    elif uc_error.errno == UC_ERR_INSN_INVALID:
        os.kill(os.getpid(), signal.SIGILL)
    else:
        # Not sure what happened
        os.kill(os.getpid(), signal.SIGABRT)
