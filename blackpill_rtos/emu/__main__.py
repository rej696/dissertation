from emu.emulator import Emulator, FLASH_START_ADDRESS, fuzz_start
from unicornafl import uc_afl_fuzz_custom
from functools import partial
from pgf.utils import blackbox_generator
import os
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


def manual_handler(filename, input_file, grammar, debug, dbc_addr, address_space):
    emu = Emulator(filename, FLASH_START_ADDRESS, False, dbc_addr, False)

    print(f"Input: {input_file}")
    with open(input_file, "rb") as f:
        input = bytearray(f.read())
        if grammar:
            emu.spp_handler.set_input(input)
        else:
            emu.spp_handler.set_raw_input(input)

    result = fuzz_start(emu.uc, emu)
    print(f"\tResult: {result}")
    print(f"\tCoverage: {(len(emu.cov) / len(address_space))* 100: .2f}%")


def cov_handler(
    filename, fuzz_input_filename, grammar, debug, dbc_addr, cov_path, address_space
):
    coverage = set()
    # get ordered list of files
    files = sorted(
        filter(lambda x: not x.is_dir(), os.scandir(cov_path)), key=(lambda x: x.name)
    )
    for input_file in files:
        emu = Emulator(filename, FLASH_START_ADDRESS, False, dbc_addr, True)
        print(f"Input: {input_file.name}")
        with open(input_file, "rb") as f:
            input = bytearray(f.read())
            if grammar:
                emu.spp_handler.set_input(input)
            else:
                emu.spp_handler.set_raw_input(input)

        result = fuzz_start(emu.uc, emu)
        if not address_space.issuperset(emu.cov):
            print("ERROR")
        coverage.update(emu.cov)

        print(f"\tResult: {result}")
        print(f"\tCoverage: {(len(emu.cov) / len(address_space))* 100: .2f}%")
        print(f"\tTotal Coverage: {(len(coverage) / len(address_space))*100: .2f}%")


def spp_grammer_input_cb(emu):
    # Print hello world
    emu.spp_handler.set_input(b"\xf0\x00\x00")

    # Set u8 parameter
    emu.spp_handler.set_input(b"\xa0\x20\x01\xa5")
    # Print u8 Parameter
    emu.spp_handler.set_input(b"\x20\x01\x00")

    # Set u32 parameter
    emu.spp_handler.set_input(b"\x50\x21\x04\xde\xad\xbe\xef")
    # Print u32 Parameter
    emu.spp_handler.set_input(b"\xe0\x02\x00")

    # Send them all in one go
    emu.spp_handler.set_input(
        b"\xf0\x00\x00\xf0\x20\x01\x7d\xf0\x01\x00\xf0\x21\x04\xca\xfe\xba\xbe\xf0\x02\x00\xf0\x02\x00"
    )


def spp_raw_input_cb(emu):
    # Print hello world
    emu.spp_handler.set_raw_input(
        bytearray(b"\xfa\x10\x00\xdb\xdc\x00\x00\x00\x00\xd0\xc0")
    )

    # Set u8 parameter
    emu.spp_handler.set_raw_input(
        bytearray(b"\xab\x10\x02\xdb\xdc\x00\x00\x01\x00\xa5\x78\xc0")
    )
    # Print u8 Parameter
    emu.spp_handler.set_raw_input(
        bytearray(b"\x2a\x10\x00\xdb\xdc\x00\x00\x00\x01\xd1\xc0")
    )

    # Set u32 parameter
    emu.spp_handler.set_raw_input(
        bytearray(b"\x5e\x10\x02\xdb\xdc\x00\x00\x04\x01\xde\xad\xbe\xef\x0f\xc0")
    )
    # Print u32 Parameter
    emu.spp_handler.set_raw_input(
        bytearray(b"\xea\x10\x00\xdb\xdc\x00\x00\x00\x02\xd2\xc0")
    )

    # Send them all in one go
    emu.spp_handler.set_raw_input(
        bytearray(
            b"\xfa\x10\x00\xdb\xdc\x00\x00\x00\x00\xd0\xc0\xfb\x10\x02\xdb\xdc\x00\x00\x01\x00\x7d\x50\xc0\xfa\x10\x00\xdb\xdc\x00\x00\x00\x01\xd1\xc0\xfe\x10\x02\xdb\xdc\x00\x00\x04\x01\xca\xfe\xba\xbe\x17\xc0\x0a\x10\x00\xdb\xdc\x00\x00\x00\x02\xd2\xc0"
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
        "-m",
        "--manual-input",
        type=str,
        default="",
        help="Path to the file containing the manually defined input to load",
    )

    parser.add_argument(
        "-c",
        "--cov",
        type=str,
        default="",
        help="Path to the folder containing the input files",
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

        if args.cov or args.manual_input:
            address_space = {
                int(addr, 16)
                for addr in subprocess.check_output(
                    "arm-none-eabi-objdump -d "
                    + args.elf
                    + " | awk '$1 ~ /8.*:/ && $3 !~ /word/ { print $1 }' | tr -d ':'",
                    shell=True,
                )
                .decode("utf-8")
                .split("\n")
                if addr
            }

    if args.cov:
        # afl fuzz mode
        signal.signal(signal.SIGINT, sigint_handler)
        cov_thread = threading.Thread(
            target=partial(
                cov_handler,
                args.firmware,
                args.input,
                args.grammar,
                args.debug,
                dbc_range,
                args.cov,
                address_space,
            )
        )
        cov_thread.start()
        cov_thread.join()

    elif args.input:
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
    if args.manual_input:
        signal.signal(signal.SIGINT, sigint_handler)
        manual_thread = threading.Thread(
            target=partial(
                manual_handler,
                args.firmware,
                args.manual_input,
                args.grammar,
                args.debug,
                dbc_range,
                address_space,
            )
        )
        manual_thread.start()
        manual_thread.join()

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
