from emu.emulator import Emulator, FLASH_START_ADDRESS
import sys

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("provide file path as argument")
        sys.exit(-1)
    emu = Emulator(sys.argv[1], FLASH_START_ADDRESS)
    emu.start()
