from unicorn import *
from unicorn.x86_const import *
from unicornafl.unicornafl import uc_afl_fuzz

uc = Uc(UC_ARCH_X86, UC_MODE_32)

# Can only map memory in increments of page sizes for x86 which is 4KB (0x1000)
uc.mem_map(0x1000, 4096)
uc.mem_write(0x1000, b"hello")
print(str(uc.mem_read(0x1000, 5), encoding="utf-8"))

stack_base = 0x0010_0000
stack_size = 0x0010_0000
uc.mem_map(stack_base, stack_size)
uc.mem_write(stack_base, b"\x00" * stack_size)
# point the stack pointer to the middle of the stack,
# sometimes we emulate code from the middle, and the stack pointer might move up as well
# as down, perhaps the code hasn't setup the stack properly.
uc.reg_write(UC_X86_REG_ESP, stack_base + stack_size // 2)

# setup code
code = bytes.fromhex('b8 02 00 00 00 bb 03 00 00 00 03 c3')
target_base = 0x0040_0000
target_size = 0x0010_0000
uc.mem_map(target_base, target_size, UC_PROT_ALL)
uc.mem_write(target_base, b"\x00" * target_size)
uc.mem_write(target_base, code)

# start emulation (start address, end address)
uc.emu_start(target_base, target_base + len(code), timeout=0, count=0)

eax = uc.reg_read(UC_X86_REG_EAX)
print(f"EAX: {eax}")
