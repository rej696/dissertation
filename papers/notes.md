# Zhang 2024 - Survey of Protocol Fuzzing
## Summary
- What challenges are there with protocl fuzzing
- Categorization and overview of existing research efforts

## Notes:
- protocols can be stateful/stateless, open/propriatory, dependent on hardware
- protocol fuzzing has:
    - high communication complexity:
        - state machines and constraints in the communication
        - protocols have extra features beyond basic message exchange, such as timing, authentication, confidentiality
    - constrained environment:
        - coupling/dependency on hardware
        - need for grey box testing information from the target

general fuzzer has three basic components:
- input generator
- executor
- bug collector

section 7.3 suggests a direction for future research is fuzzing characterised protocol
targets such as domain specific protocols such as those used in satellite
communication

> Presently, fuzzing research for these protocols is relatively scarce,
> presenting an opportunity for the academic community to improve testing
> effectiveness and security through the development of new fuzzing techniques
> and tools.

# Yun 2022 - Fuzzing of Embedded Systems: A Survey

# Clements 2020 - Halucinator
https://www.youtube.com/watch?v=7mFqTjfLuEM

Explains the potential benefits and challenges of rehosting (emulating) over testing on hardware

"Halucinators goal is to enable scalable firmware testing without requiring specialised hardware"

Peripherals are the biggest problem. QEMU allows execution of instruction sets, but doesn't model mcu peripherals.

explanation of concept and use of HAL's in embedded software
> Halucinator enables replacing HAL's with other libraries with high level
> implementations. Transforming the re-hosting scaling problem from supporting
> 10,000's of devices to dozens of HALS

make use of python models of hardware (e.g. I2C model) and python hooks that
are called in the Emulator instead of HAL functions, so that when the firmware
being emulated calls a HAL API, it uses the python model instead.

libMatch uses binary analysis to find function names

built fuzzing oriented version of halucinator called hal-fuzz, built on afl-unicorn
dealt with firmware fuzzing issues such as:
- termination detection
- non-determinisim from timers and interrupts

fuzzed at different levels of abstraction (i.e low level HAL and higher level API's) and found different sets of bugs for each.


# Scharnowski 2022 - Fuzzware
https://www.youtube.com/watch?v=GBqW5u-0DkI

- Binary ISA Emulation and Fuzzing tool
- Dynamic Symbol analysis for generating constraint models for fuzzing inputs for memory mapped IO
- fully automated (minimal configuration)

Outperforms other fuzz testing tools

# Scharnowski 2023 - A Case Study of Fuzzing Satellite Firmware (Fuzzware)
## Contributions
- Applying Fuzzware to fuzz test 3 different satellite payload data handling images
- case study of manually optimizing fuzzing configurations and the impact on performance metrics
- derive challenging areas of current solutions for fuzzing satellite firmware and identify possible areas of future work

## Challenges:
### Elaborate boot processes
these can cause the fuzzer to get stuck trying to get out of the boot process, and require manual configuration.

### Interrupt timing requirements and dma.
Fuzzware's MMIO focused approach means that the tool spends less time
analysing the impact of automatically analysising the timing requirements of
the firmware

## Future Work
Focused on increasing automation on generating "robust and target aware fuzzing configuration"
Improvements could include automated handling of hardware features like DMA, and more efficiently dealing with firmware boot process

# Scharnowski/Worner 2023 - Hoedur
https://www.youtube.com/watch?v=lqZ945w6OH8
https://github.com/fuzzware-fuzzer/hoedur

Embedded Firmware Fuzzing using Multi-stream inputs to improve Fuzzware

Current fuzzer input is a single stream. This can cause issues if a change in
the input means that different MMIO calls are made (or are made out of order),
which messes up the fuzzers model of the inputs. "the avalanche effect)

Hoedur aims to provide the fuzzer with extended feedback, and split up the
inputs into different streams (i.e for different threads/tasks/ISR)

While Fuzzware uses AFL as a drop in fuzzer and implements improvements to the
emulation, Hoedur implements its own fuzzer based on libFuzzer using borrowed
parts from AFL and AFL++, written in Rust.

## Future Work
fuzzing a uart device where one MMIO register with input data is mapped to a
single data stream, where a specialised grammer fuzzer can provide the data
without interference from other MMIO accesses.

# Seidel 2023 - Forming Faster Firmware Fuzzers
https://www.youtube.com/watch?v=mLnLs6tA7bM

Most work in embedded fuzzing space is focused on solving the problem of
peripherals, and uses general purpose emulators like QEMU and Unicorn (Based on
QEMU)

Identify that the focus in embedded devices is on Arm Cortex-M devices (ARMv7-M
chips), and that certain ARMv8-A cores have compatibility with AArch32 and
Thumb instruction sets, therefore it would be possible to execute binaries for
small embedded devices "near-natively" on these ARMv8-A chips. This outperforms
rehosting approaches built on top of general purpose emulators.

the approach mirrors memory layout of the embedded device in userspace, and you can use the hardware mmu to detect memory violations (rather than softMMU used in QEMU which has a lot of overhead

compared with Halucinator and Fuzzware
145x faster at gaining coverage than Fuzzware

# 2024 Willbold - Scaling Software Security Analysis to Satellites





# Possible Projects
- I2C Fuzzer (black box fuzz testing of I2C devices?)
    - Fuzz testing a Clydespace EPS?
- SpacePacket / CCSDS / CSP Protocol Fuzzer
- fuzz testing libCSP
- Fuzz testing Gen1?

development of a fuzzer, and then testing on some example device
fuzz testing a specific device


unicorn-afl fuzzing of libcsp in an embedded device

applying a protocol fuzzer to fuzzware/hoeder input data stream (i.e. some grammer fuzzer for creating spacepackets?)
