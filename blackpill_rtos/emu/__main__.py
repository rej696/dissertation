from emu.emulator import Emulator, FLASH_START_ADDRESS, fuzz_start
from unicornafl import uc_afl_fuzz_custom
from functools import partial
from ccsds.utils import blackbox_generator
import sys
import signal
import threading
import subprocess
import argparse


def fuzz_handler(filename, fuzz_input_filename, grammar, debug, dbc_addr):
    emu = Emulator(filename, FLASH_START_ADDRESS, False, dbc_addr)

    def input_cb(uc, input_bs, persisent_round, emu) -> bool:
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


def spp_grammer_input_cb(emu):
    # Print hello world
    emu.spp_handler.set_input(b"\xf0\x00\x00")

    # Set u8 parameter
    emu.spp_handler.set_input(b"\xf0\x20\x01\xa5")
    # Print u8 Parameter
    emu.spp_handler.set_input(b"\xf0\x01\x00")

    # Set u32 parameter
    emu.spp_handler.set_input(b"\xf0\x21\x04\xde\xad\xbe\xef")
    # Print u32 Parameter
    emu.spp_handler.set_input(b"\xf0\x02\x00")

    # Send them all in one go
    emu.spp_handler.set_input(
        b"\xf0\x00\x00\xf0\x20\x01\x7d\xf0\x01\x00\xf0\x21\x04\xca\xfe\xba\xbe\xf0\x02\x00\xf0\x02\x00"
    )


def spp_raw_input_cb(emu):
    # Print hello world
    emu.spp_handler.set_raw_input(
        bytearray(b"\x0a\x10\x00\xdb\xdc\x00\x00\x00\x00\xd0\xc0")
    )

    # Set u8 parameter
    emu.spp_handler.set_raw_input(
        bytearray(b"\x0b\x10\x02\xdb\xdc\x00\x00\x01\x00\xa5\x78\xc0")
    )
    # Print u8 Parameter
    emu.spp_handler.set_raw_input(
        bytearray(b"\x0a\x10\x00\xdb\xdc\x00\x00\x00\x01\xd1\xc0")
    )

    # Set u32 parameter
    emu.spp_handler.set_raw_input(
        bytearray(b"\x0e\x10\x02\xdb\xdc\x00\x00\x04\x01\xde\xad\xbe\xef\x0f\xc0")
    )
    # Print u32 Parameter
    emu.spp_handler.set_raw_input(
        bytearray(b"\x0a\x10\x00\xdb\xdc\x00\x00\x00\x02\xd2\xc0")
    )

    # Print Hello world 4 times
    emu.spp_handler.set_raw_input(
        bytearray(
            b"\x0a\x10\x00\xdb\xdc\x00\x00\x00\x00\xd0\xc0\x0a\x10\x00\xdb\xdc\x00\x00\x00\x00\xd0\xc0\x0a\x10\x00\xdb\xdc\x00\x00\x00\x00\xd0\xc0\x0a\x10\x00\xdb\xdc\x00\x00\x00\x00\xd0\xc0"
        )
    )


def emu_handler(filename, grammar, debug, dbc_range):
    emu = Emulator(filename, FLASH_START_ADDRESS, debug, dbc_range)
    if grammar:
        spp_grammer_input_cb(emu)
    else:
        spp_raw_input_cb(emu)
    emu.start()


def blackbox_handler(filename, grammar, debug, dbc_range):
    emu = Emulator(filename, FLASH_START_ADDRESS, debug, dbc_range)
    gen = blackbox_generator()
    if grammar:
        emu.spp_handler.set_input(gen)
    else:
        emu.spp_handler.set_raw_input(gen)

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
        "-b",
        "--blackbox",
        default=False,
        action="store_true",
        help="Enable infinite blackbox fuzzing",
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
        # afl fuzz mode
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
    elif args.blackbox:
        # blackbox fuzz mode
        # Run emu in thread to kill application on KeyboardInterrupt <C-c>
        signal.signal(signal.SIGINT, sigint_handler)
        emu_thread = threading.Thread(
            target=partial(
                blackbox_handler, args.firmware, args.grammar, args.debug, dbc_range
            )
        )
        emu_thread.start()
        emu_thread.join()

    else:
        # emu mode

        # Run emu in thread to kill application on KeyboardInterrupt <C-c>
        signal.signal(signal.SIGINT, sigint_handler)
        emu_thread = threading.Thread(
            target=partial(
                emu_handler, args.firmware, args.grammar, args.debug, dbc_range
            )
        )
        emu_thread.start()
        emu_thread.join()


if __name__ == "__main__":
    main()
