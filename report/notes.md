# Notes

## Title
- An Investigation into Instruction Emulation and Fuzz Testing as a Methodology for Developing Spacecraft Flight Software

## Discussion
- Building the Emulator and harness alongside the flight software (and target hardware) outlined many issues:
    - individual threads initialising shared data structures bug was found due to emulation sending data immediately after boot which would be difficult to do manually on target hardware.

- Time and Difficulty emulating peripherals, especially chip specific ones like UART, as well as ARM-Cortex generic ones like SCB and NVIC

- Fuzzing takes a long time, and so not effective to run fuzzer on software still in development that could change (i.e. not that useful as a tool for use alongside development, unlike unit tests)

## Introduction
- What:
    - Emulation (rehosting) and Fuzz testing of embedded space flight software
    - Investigation of fuzzing and emulation as a methodology for developing software
    - Investigation into use of grammar layer in fuzzer test harness to increase coverage
- Why:
    - Easy method for verifiction of software?
    - Hardware availability during development
    - difficulties with fuzz testing on target hardware (papers?)
    - fuzzing protocols with mmio registers can take longer or are unable to reach specific coverage (e.g. checksums, encryption) (papers?)
        - Prototyping this in order to be implemented in other tools like hoedur
- How:
    - unicorn based emulator for stm32
    - modelling cortex-m and stm32 peripherals in python
    - spacepacket grammar protocol adapter (?) streaming bytes from fuzzer into fuzzer input
    - unicornafl integration to run emulator (test harness) under aflplusplus
    - developing simple but representative flight software for an stm32 (why, used in industry, examples?)
    -

## Design
### Flight Software
- Design by Contract
    - Triggering an DBC_fault_handler is an easy way for the emulator/fuzzer to detect a crash/bugs for a logical error
- Simple RTOS
    - represent actual systems, rather than taking a superloop approach which would be easier to fuzz
    - reduced effort for emulation (we know exactly what peripherals are used for the simple rtos (based on MIROS), and so only need to emulate those peripherals)
- Action/Parameter/Telemetry Remote Procedure Call system based on spacepacket
    - Simplified version of paradigmn common with space flight software

### Emulator
- Unicorn
    - Well known and used in many different papers
    - Python API (easier development)
- Modelling Peripherals
    - mapping memory regions for only those peripherals used
    - using unicorn mmio callbacks for setting/getting values and triggering custom behaviour, such as setting interrupts to pending or writing data to stdout
    - modelling cortex-m peripherals (NVIC, Systick) and stm32 peripherals (USART)
    - Any peripheral not modelled that attempts to access triggers a unicorn exception, making bug/error detection easier (accessing any non-modelled is an indication of a bug in the flight software or the emulator)

### Fuzzer
- Unicornafl
    - api built into afl that allows fuzzing emulated unicorn programs without any additional instrumentation
    - slower than fuzzing native binaries
- Spacepacket grammar input modification



