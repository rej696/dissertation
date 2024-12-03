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


## Requirements?
## System Requirements
- The system shall demonstrate the application of rehosting and fuzzing techniques for the verification of satellite flight software
- The system shall be sufficiently simple

### Flight Software Requirements
i.e. what does the target need to do to make it look like flight software
- "Flight Software" covers a wide range of different types of devices,

- Implement a typical interface for interaction with flight software
    - sending commands (actions)
    - setting and retrieving configurable data (parameters)
    - reading values (telemetry)

- Implement spacepacket protocol communication over serial

- Exhibit rtos (concurrency) like behaviours
    - Spaceflight software systems, like

### Emulator
- The emulator shall
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



### Bugs found by fuzzer:
- Buffer overflow in kiss_frame_unpack routine, where multiple circular buffers of data were being written into a single fixed length array (to handle intermittent commss with no check how big the resulting unpacked size would be before writing to the buffer)
    - This was discovered while developing the blackbox fuzzer, and resulted in the program timing out, rather than trigging any fault handler. As such it was quite difficult to debug.
    - This was fixed by adding a guard to the kiss_frame_unpack function where if the index for writing the next byte to the buffer exceeded the buffer size, the buffer would be reset
    - This condition was also made more uncommon by increasing the size of the array to the max size of the circular buffer, so a single cbuf of data wouldn't trigger the issue.
- Framing issues when sending data before implementing the kiss framing
    - This was discovered when developing the emulator which was sending all the spacepackets at the same time, causing multiple packets to get processed as one, and indiciating the need for framing. Initially, some fixes were implemented in the spacepacket process function, before properly implementing KISS framing
- shared global cbuf for passing data from uart to packet thread was being initialised in the packet thread, which was first called after the uart. therefore, if the uart had received data before the packet thread was started, this would be lost. This was found when developing the emulator, as this first sent all the packet to the uart immediately on "boot", which wasn't something that had been manually tested on the hardware.
    - This also triggered a bug in the circular buffer implementation, where the read function didn't correctly check if the circular buffer was empty, and so would read invalid data. This was identified thanks to the use of stack paint when initialsing the stacks for each thread in the rtos, which
    - TODO remember and explain this (perhaps look at the commit and memory address 0x20003ed8 for memory)
- Bound checking error when validating the spacepacket apid. discovered through use of blackbox fuzz testing followed by manual testing on hardware
    - The check against the maximum apid range was >= rather than >, so the telemtry requests did not work.
- Error with reading spacepacket when uart buffer read in two parts. There was a logical error that meant that the packet thread would still try to parse spacepackets even if the frame unpack function had not marked the frame as complete.
    - Discovered using blackbox fuzzing and manual testing
- Blackbox Emulator Fuzzer:
    - Identified DBC Assert being triggered by invalid frames (see screenshots)
    - Modified condition to fail gracefully.


A combination of Blackbox fuzzing and manually setting input data on the target
hardware allowed for easier observation of the system than using the fuzzer and
emulator. It was quicker to notice a behaviour that didn't seem right for a
given input, capture the invalid input and manually send it after putting some
debug statements into the code to analyse what the issue was.

using the blackbox fuzzer also allow the grammar input filtering scheme to be
refined to hit as much coverage as possible. Initial implementations had the
length of the spacepacket data payload varying greatly up to the maximum as
defined in the ICD. However, for testing the flight software, this was
unneccassary, as the action/parameter/telemetry scheme didn't allow for data
payloads greater than 6, and so most of the packets generated by the filter
were rejected. Tuning the format of the input to the spacepacket generator
helped both the blackbox and rehosting fuzzers hit nominal and error cases more
effectively.

One of the concerns with the input filtering, is that by adding so many
constraints to achieve the nominal case (i.e. valid headers and checksums) it
also made it more difficult to get the fuzzer to hit error conditions, or the
fuzzer hit similar errors. In the initial impelementation, invalid apid was
often hit, as the input filter gave a 50% chance of the apid being invalid by
checking a single bit in the input. But other header fields like the type were
always valid, as there was not a way to tell the filter to make those fields
invalid.

Testing with the blackbox fuzzer identified several questions around the design
of the flight software. For example, the flight software had been written to
respond to a action/paramter/telemetry request with a spacepacket containing
the status code in its first byte. This was designed to provide information to
a hypothetical operator that an action/set-param had successfully been carried
out, and if not, what the error was with the operation. However, when carrying
out blackbox fuzz testing, it was identified that errors in parsing the
received spacepackets, such as those due to validating the header fields or
length of the payload, did not respond with status codes. This seemed like an
oversight in the design, as without the response there would be no way for an
operator to know what the error was. Equally, if the spacepacket were unable to
be parsed correctly, there was no way to know if a response would be expected.
Two approaches could be implemented to improve this situation. Telemetry
handlers could be implemented to keep track of and return a count of each type
of spacepacket error, and the flight software could send responses to malformed
spacepackets.

As unicornafl took a long time to run, it was left for long periods with bugs
only analysed after. This approach is less useful for testing during
development, as one logical error (for example, the bounds checking error)
caused a large number of inputs to be incorrectly executed in the fuzzer, and
any other results beyond that bug would need to be discarded, and the process
started again. It would seem using fuzzing tools like AFL is more appropriate
for software that has already been extensively tested and marked as complete,
and the fuzzer should be used to try and catch any remaining errors, rather
than as a tool during development for verifying new code.



### Extensions:
        # FIXME run without interrupts until rtos_run re-enables interrupts? after this boot process is complete, then we can "tick" using emu start timeouts and handle interrupts inbetween without needing a code callback?
        # could also do WFI in rtos_on_idle, and then skip to the next systick/pendsv interrupt?
        # rtos_schedule triggers pendsv, which is typically executed in the systick interrupt. need to have pendsv trigger after systick has returned (systick higher priority than pendsv) this should happen by default if we run "application" emulator code (non-interrupts) in increments of the systick frequency
