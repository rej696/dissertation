from emu.emulator import Emulator, FLASH_START_ADDRESS, fuzz_start
from unicornafl import uc_afl_fuzz_custom
from functools import partial
import sys
import signal
import threading
import time
import subprocess
import argparse
import os


def fuzz_handler(filename, fuzz_input_filename, grammar, debug, dbc_addr):
    emu = Emulator(filename, FLASH_START_ADDRESS, False, dbc_addr)
    # setup fuzzing stuff

    # afl fork server
    print("Start AFL Fork Server")
    end_address = list(dbc_addr)[0]  # DBC_Exception?
    # FIXME this function doesn't exist anymore, will have to make use of
    # the place_input_callback and validate_crash_callback functions of the
    # uc.afl_fuzz function (that does exist)
    # Need to experiment with afl_fuzz function if it works with the trampoline method
    # Alternatively might be able to fuzz the whole script without using unicorn afl and by just running the emulator under the fuzzer?
    # afl_mode = emu.uc.afl_forkserver_start([end_address])

    # The most likely solution will be to use uc_afl_fuzz_custom, which takes a fuzzing_callback function, which could be our emu.start() function
    # FIXME need right arguments
    def input_cb(uc, input_bs, persisent_round, emu) -> bool:
        # # read fuzzing input data
        # while not os.path.isfile(fuzz_input_filename):
        #     print("waiting for file")
        #     time.sleep(1)
        # fuzz_input = b""
        # with open(fuzz_input_filename, "rb") as f:
        #     fuzz_input = f.read()
        # store fuzzing input data somewhere to go into uart?
        fuzz_input = bytearray(input_bs)
        if grammar:
            emu.spp_handler.set_input(fuzz_input)
        else:
            emu.spp_handler.set_raw_input(fuzz_input)

    uc_afl_fuzz_custom(
        emu.uc,
        input_file=fuzz_input_filename,
        place_input_callback=input_cb,
        fuzzing_callback=fuzz_start,
        data=emu,
    )

    # # start emulator
    # emu.start()


def spp_grammer_input_cb(emu):
    # Print hello world
    emu.spp_handler.set_input(b"\x20\x00\x00")

    # Set u8 parameter
    emu.spp_handler.set_input(b"\xC8\x01\x00\xa5")
    # Print u8 Parameter
    emu.spp_handler.set_input(b"\xE0\x00\x01")

    # Set u32 parameter
    emu.spp_handler.set_input(b"\xA8\x04\x01\xde\xad\xbe\xef")
    # Print u8 Parameter
    emu.spp_handler.set_input(b"\xC0\x00\x02")


def spp_raw_input_cb(emu):
    # Print hello world
    emu.spp_handler.set_raw_input(
        bytearray(b"\x05\x10\x00\xdb\xdc\x00\x00\x00\x00\xd0\xc0")
    )

    # Set u8 parameter
    emu.spp_handler.set_raw_input(
        bytearray(b"\x07\x10\x02\xdb\xdc\x00\x00\x01\x00\xa5\x78\xc0")
    )
    # Print u8 Parameter
    emu.spp_handler.set_raw_input(
        bytearray(b"\x00\x10\x00\xdb\xdc\x00\x00\x00\x01\xd1\xc0")
    )

    # Set u32 parameter
    emu.spp_handler.set_raw_input(
        bytearray(b"\xff\x10\x02\xdb\xdc\x00\x00\x04\x01\xde\xad\xbe\xef\x0f\xc0")
    )
    # Print u32 Parameter
    emu.spp_handler.set_raw_input(
        bytearray(b"\x32\x10\x00\xdb\xdc\x00\x00\x00\x02\xd2\xc0")
    )

    # Print Hello world 4 times
    emu.spp_handler.set_raw_input(
        bytearray(
            b"\x05\x10\x00\xdb\xdc\x00\x00\x00\x00\xd0\xc0\x10\x00\xdb\xdc\x00\x00\x00\x00\xd0\xc0\x10\x00\xdb\xdc\x00\x00\x00\x00\xd0\xc0\x10\x00\xdb\xdc\x00\x00\x00\x00\xd0\xc0"
        )
    )


def emu_handler(filename, grammar, debug, dbc_range):
    emu = Emulator(filename, FLASH_START_ADDRESS, debug, dbc_range)
    if grammar:
        spp_grammer_input_cb(emu)
    else:
        spp_raw_input_cb(emu)
    emu.start()


def sigint_handler(sig, frame):
    """Handler for <C-c>"""
    print("User Interrupted")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Emulator for blackpill rtos firmware")

    parser.add_argument("firmware", type=str, help="Path to the binary firmware")

    parser.add_argument(
        "-i",
        "--input",
        type=str,
        default="",
        help="Path to the file containing the mutated input to load",
    )

    parser.add_argument(
        "--elf",
        type=str,
        default="build/firmware.elf",
        help="Path to the elf file containing the symbol table for parsing the DBC Handler Address",
    )

    parser.add_argument(
        "-g",
        "--grammar",
        default=False,
        action="store_true",
        help="Enable grammar based inputs",
    )

    parser.add_argument(
        "-d", "--debug", default=False, action="store_true", help="Enable debug tracing"
    )

    args = parser.parse_args()

    if args.elf:
        symbols = subprocess.check_output(f"readelf {args.elf} -s", shell=True).decode(
            "utf-8"
        )
        dbc = [line for line in symbols.split("\n") if "DBC_fault_handler" in line][
            0
        ].split()
        dbc_addr = int(dbc[1], base=16) - 1
        dbc_size = int(dbc[2])
        dbc_range = range(dbc_addr, dbc_size + dbc_addr)

    if args.input:
        # fuzz mode
        signal.signal(signal.SIGINT, sigint_handler)
        fuzz_thread = threading.Thread(
            target=partial(
                fuzz_handler,
                args.firmware,
                args.input,
                args.grammar,
                args.debug,
                dbc_range,
            )
        )
        fuzz_thread.start()
        fuzz_thread.join()
    else:
        # emu mode

        # input_cb = spp_grammer_input_cb
        input_cb = spp_raw_input_cb

        # Run emu in thread to kill application on KeyboardInterrupt <C-c>
        signal.signal(signal.SIGINT, sigint_handler)
        emu_thread = threading.Thread(
            target=partial(
                emu_handler, args.firmware, args.grammar, args.debug, dbc_range
            )
        )
        emu_thread.start()
        emu_thread.join()


def old_main():
    if len(sys.argv) < 2:
        print("provide file path as argument")
        sys.exit(-1)

    # read dbc assert memory range
    dbc_range = range(0x800028C, 0x80002A8)
    if len(sys.argv) == 4:
        dbc_range = range(int(sys.argv[2], base=16), int(sys.argv[3], base=16))

    # Debug information?
    debug = False

    # input_cb = spp_grammer_input_cb
    input_cb = spp_raw_input_cb

    # Run emu in thread to kill application on KeyboardInterrupt <C-c>
    signal.signal(signal.SIGINT, sigint_handler)
    emu_thread = threading.Thread(
        target=partial(emu_handler, sys.argv[1], input_cb, debug, dbc_range)
    )
    emu_thread.start()
    emu_thread.join()


if __name__ == "__main__":
    main()
