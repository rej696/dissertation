# STM32 Blackpill Baremetal Application
This is a bare metal application for the STM32F411CE "Blackpill" dev board.

The intention for this software is to create a simple serial device that can
then be reverse engineered to run on a unicorn emulator.

## TODO
- Implement some protocol (perhaps include libCSP?)
- Fuzz test a specific function in the main program
- use DBC Asserts with fuzz testing?

## Links
- [Unicorn Engine Notes](https://github.com/alexander-hanel/unicorn-engine-notes)
- [Unicorn AFL Python Example](https://github.com/AFLplusplus/AFLplusplus/tree/stable/unicorn_mode/samples/python_simple)
