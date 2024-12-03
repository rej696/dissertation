# STM32 Flight Software Development, Emulation, and Fuzzing
This project consists of:
- A bare metal "Flight Software" application for the STM32F411CE "Blackpill" microcontroller board:
    - Remote Procedure Call implementation over Serial using Spacepackets and KISS framing
    - Design by Contract
    - Basic RTOS implementation inspired Miro Sameks MIROS
- A python emulator/fuzzing test harness using unicorn `emu`:
    - Arm Cortex-M and STM32 Peripheral models
    - Interrupt handling and context switching
    - A protocol grammar filter for converting a raw byte stream into valid input data (spacepackets with checksums in KISS frames)
    - black box fuzzing (with or without grammar filtering)
- A "Ground Segment" python cli tool `spp`:
    - reading/writing packets to a connected development board
    - on target black box fuzzing (with or without grammar filtering)

## Instructions
### Docker
All dependencies (beyond hardware) are included in the Dockerfile, and hardware
independent functions of the project can be run within the docker image.

You can install docker on your machine following the [instructions online](https://docs.docker.com/engine/install/)

You can build the docker image with `docker build -t rej696/afl:latest .`, or `make docker-build`

You can then run the container and drop into a shell using
`docker run --rm -it --name fuzz -v $(pwd):/src rej696/afl bash` or `make docker-bash`

### STM32 "Flight Software" Application
To compile the stm32 flight software, you can use the docker container, or install:
- make
- arm-none-eabi-gcc toolchain

Compile with `make build`

#### Hardware
You need:
- The [stm32 blackpill development board](https://thepihut.com/products/stm32f411-blackpill-development-board)
    - [blackpill information](https://stm32-base.org/boards/STM32F411CEU6-WeAct-Black-Pill-V2.0.html)
- Two [ftdi cables](https://thepihut.com/products/ftdi-serial-ttl-232-usb-cable) connected to usart 1 and usart 2 with some jumper wires (see blackpill pinout)
- An [st-link v2](https://thepihut.com/products/st-link-stm8-stm32-v2-programmer-emulator) connected to serial wire debug

To interact with hardware, I recommend you install the arm-none-eabi toolchain locally.
You also need to install the [st-link tools](https://github.com/stlink-org/stlink).

With the st-link connected to the board, you can flash the device with `make flash`

With usart2 connected to your PC with the ftdi cable, you can monitor the debug
output from the stm32 with `./spp --dev /dev/ttyUSB1 log`. Make sure the --dev
argument matches the port your ftdi cable is using.

With usart1 connected to your PC with the ftdi cable, you can send/receive
packets to/from the stm32 with the `spp` python tool.

You can use the tool to trigger specific functions, for example `./spp --dev
/dev/ttyUSB0 action 0` sends a packet to the device to run action with id 0.

You can also use the "blackbox fuzzer" functionality of the tool with `./spp
--dev /dev/ttyUSB0 fuzz --timeout 5`. This will periodically send packets
created from a random bytestream through the protocol grammar filter.

run `./spp --help` for more information.

### Emulator
You can run the compiled flight software using the python emulator










## Links
- [Unicorn Engine Notes](https://github.com/alexander-hanel/unicorn-engine-notes)
- [Unicorn AFL Python Example](https://github.com/AFLplusplus/AFLplusplus/tree/stable/unicorn_mode/samples/python_simple)
