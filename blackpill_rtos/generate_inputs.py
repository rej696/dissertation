#!/usr/bin/env/python

grammar_examples = {
    "hello_action": b"\x05\x00\x01\x00",
    "set_u8_param": b"\x07\x80\x02\x01\xA5",
    "print_u8_param": b"\x00\x00\x01\x01",
    "set_u32_param": b"\xFF\x80\x05\x02\xDE\xAD\xBE\xEF",
    "print_u32_param": b"\x32\x00\x01\x02",
    "all_together": b"\x05\x00\x01\x00\x07\x80\x02\x01\xA5\x00\x00\x01\x01\xFF\x80\x05\x02\xDE\xAD\xBE\xEF\x32\x00\x01\x02"
}

raw_examples = {
    "hello_action": b'\x05\x10\x00\xc0\x00\x00\x00\x00',
    "set_u8_param": b'\x07\x10\x02\xc0\x00\x00\x01\x01\xa5',
    "print_u8_param": b'\x00\x10\x00\xc0\x00\x00\x00\x01',
    "set_u32_param": b'\xFF\x10\x02\xc0\x00\x00\x04\x02\xde\xad\xbe\xef',
    "print_u32_param": b'\x32\x10\x00\xc0\x00\x00\x00\x02',
    "all_together": b'\x05\x10\x00\xc0\x00\x00\x00\x00\x07\x10\x02\xc0\x00\x00\x01\x01\xa5\x00\x10\x00\xc0\x00\x00\x00\x01\xFF\x10\x02\xc0\x00\x00\x04\x02\xde\xad\xbe\xef\x32\x10\x00\xc0\x00\x00\x00\x02',
}

for name, data in grammar_examples.items():
    with open(f"grammar_fuzz_inputs/{name}.bin", "wb") as f:
        f.write(data)

for name, data in raw_examples.items():
    with open(f"raw_fuzz_inputs/{name}.bin", "wb") as f:
        f.write(data)
