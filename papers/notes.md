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


# Possible Projects
- I2C Fuzzer (black box fuzz testing of I2C devices?)
    - Fuzz testing a Clydespace EPS?
- SpacePacket / CCSDS / CSP Protocol Fuzzer
- fuzz testing libCSP
- Fuzz testing Gen1?

development of a fuzzer, and then testing on some example device
fuzz testing a specific device


unicorn-afl fuzzing of libcsp in an embedded device
