from emu.emulator import Emulator, FLASH_START_ADDRESS
from functools import partial
import sys
import signal
import threading
import time


def emu_fuzz_handler(filename, fuzz_input_filename):
    emu = Emulator(filename, FLASH_START_ADDRESS, False)
    # setup fuzzing stuff

    # afl fork server
    print("Start AFL Fork Server")
    end_address = 0x8000284 # DBC_Exception?
    afl_mode = emu.uc.afl_forkserver_start([end_address])

    # read fuzzing input data
    fuzz_input = b""
    with open(fuzz_input_filename, "rb") as f:
        fuzz_input = f.read()
    # store fuzzing input data somewhere to go into uart?
    emu.spp_handler.set_input(fuzz_input)

    # start emulator
    emu.start()



def emu_handler(filename):
    emu = Emulator(filename, FLASH_START_ADDRESS, False)
    emu.spp_handler.set_input(b"\x05\x00\x01\x00")
    emu.start()

def sigint_handler(sig, frame):
    """Handler for <C-c>"""
    print("User Interrupted")
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("provide file path as argument")
        sys.exit(-1)

    # Run emu in thread to kill application on KeyboardInterrupt <C-c>
    signal.signal(signal.SIGINT, sigint_handler)
    emu_thread = threading.Thread(target=partial(emu_handler, sys.argv[1]))
    emu_thread.start()
    emu_thread.join()
