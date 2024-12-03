#!/usr/bin/env/python
import os

grammar_examples = {
    "hello_action": b"\xf0\x00\x00",
    "set_u8_param": b"\xa0\x20\x01\xa5",
    "print_u8_param": b"\x20\x01\x00",
    "set_u32_param": b"\x50\x21\x04\xde\xad\xbe\xef",
    "print_u32_param": b"\xe0\x02\x00",
    "all_together": b"\xf0\x00\x00\xf0\x20\x01\x7d\xf0\x01\x00\xf0\x21\x04\xca\xfe\xba\xbe\xf0\x02\x00\xf0\x02\x00",
}

raw_examples = {
    "hello_action": b"\x0a\x10\x00\xdb\xdc\x00\x00\x00\x00\xd0\xc0",
    "set_u8_param": b"\x0b\x10\x02\xdb\xdc\x00\x00\x01\x00\xa5\x78\xc0",
    "print_u8_param": b"\x0a\x10\x00\xdb\xdc\x00\x00\x00\x01\xd1\xc0",
    "set_u32_param": b"\x0e\x10\x02\xdb\xdc\x00\x00\x04\x01\xde\xad\xbe\xef\x0f\xc0",
    "print_u32_param": b"\x0a\x10\x00\xdb\xdc\x00\x00\x00\x02\xd2\xc0",
    "all_together": b"\x0a\x10\x00\xdb\xdc\x00\x00\x00\x00\xd0\xc0\x0a\x10\x00\xdb\xdc\x00\x00\x00\x00\xd0\xc0\x0a\x10\x00\xdb\xdc\x00\x00\x00\x00\xd0\xc0\x0a\x10\x00\xdb\xdc\x00\x00\x00\x00\xd0\xc0",
}

for name, data in grammar_examples.items():
    os.makedirs("grammar_fuzz_inputs", exist_ok=True)
    with open(f"grammar_fuzz_inputs/{name}.bin", "wb") as f:
        f.write(data)

for name, data in raw_examples.items():
    os.makedirs("raw_fuzz_inputs", exist_ok=True)
    with open(f"raw_fuzz_inputs/{name}.bin", "wb") as f:
        f.write(data)
