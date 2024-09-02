from capstone import *
from capstone.x86 import *

CODE_FILE = 'add.bin'

code = None
with open(CODE_FILE, 'rb') as f:
    code = f.read()

assert code is not None

cs = Cs(CS_ARCH_X86, CS_MODE_32)
cs.detail = True  # provides additional information about disassembled instructions
cs.skipdata = True

registers = {}
registers[X86_REG_EAX] = 0
registers[X86_REG_EBX] = 0

registers[X86_REG_EIP] = 0

while registers[X86_REG_EIP] != len(code):
    address = registers[X86_REG_EIP]

    instruction = next(cs.disasm(code[address:address + 15], address))
    mnemonic = instruction.mnemonic
    operands = instruction.operands

    match mnemonic:
        case "mov":
            if operands[0].type == X86_OP_REG and operands[1].type == X86_OP_IMM:
                registers[operands[0].reg] = operands[1].value.imm
            else:
                print(f"\n{instruction.mnemonic} variation not implemented")

        case "add":
            if operands[0].type == X86_OP_REG and operands[1].type == X86_OP_REG:
                registers[operands[0].reg] = registers[operands[0].reg] + \
                    registers[operands[1].reg]
            else:
                print(f"\n{instruction.mnemonic} variation not implemented")
        case _:
            print(f"\nInstruction not implemented: {instruction.mnemonic}")

    registers[X86_REG_EIP] += instruction.size

print(f"\nCompleted emulation, EAX: {registers[X86_REG_EAX]}")
