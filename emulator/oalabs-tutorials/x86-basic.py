from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_REG_EAX, X86_REG_EBX, X86_OP_REG, X86_OP_IMM

code_data = bytes.fromhex('b8 02 00 00 00 bb 03 00 00 00 03 c3')

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
code = md.disasm(code_data, 0)

registers = {}
registers[X86_REG_EAX] = 0
registers[X86_REG_EBX] = 0

for instruction in code:
    mnemonic = instruction.mnemonic
    operands = instruction.operands

    match mnemonic:
        case "mov":
            if operands[0].type == X86_OP_REG and operands[1].type == X86_OP_IMM:
                registers[operands[0].reg] = operands[1].value.imm
        case "add":
            if operands[0].type == X86_OP_REG and operands[1].type == X86_OP_REG:
                registers[operands[0].reg] = registers[operands[0].reg] + \
                    registers[operands[1].reg]

print(registers[X86_REG_EAX])
