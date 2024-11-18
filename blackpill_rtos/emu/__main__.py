from emu.emulator import Emulator, FLASH_START_ADDRESS
from functools import partial
import sys
import signal
import threading
import time


def emu_handler(filename):
    emu = Emulator(filename, FLASH_START_ADDRESS, False)
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
