# Scratch

## fuzz test a tmtc interface (i.e. OBC?)
- Build a device that implements tmtc (i.e. a pretend obc?)
- use an existing tmtc device? like clydespace obc?

## Getting started
- some device with a uart (or I2C) interface and a sensor and actuator
    - I2C fuzzer?
    - I.e. a telemetry node (battery controller) that reads values from adc's and control's switches
    - If some ADC value goes below a configurable threshold, automatically switch something off.
- STM32 blackpill bare metal device with adc reads and switches, connected to scamp which is emulating some battery type device.







