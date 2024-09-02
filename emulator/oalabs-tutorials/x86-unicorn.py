from unicorn import *
from unicorn.x86_const import *

uc = Uc(UC_ARCH_X86, UC_MODE_32)

uc.mem_map(0x1000, 0x10)
uc.mem_write(0x1000, b"hello")
print(uc.mem_read(0x1000, 0x10))
