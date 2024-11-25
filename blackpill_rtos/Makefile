
PREFIX ?= arm-none-eabi
CC = $(PREFIX)-gcc
OBJCOPY = $(PREFIX)-objcopy
OBJDUMP = $(PREFIX)-objdump
GDB ?= $(PREFIX)-gdb

SYMBOL ?= main

CMSIS_INCLUDE_PATH ?= CMSIS/Include

CFLAGS  ?=  -W -Wall -Wextra -Werror -Wundef -Wshadow -Wdouble-promotion \
            -Wformat-truncation -fno-common -Wconversion \
            -g3 -Os -ffunction-sections -fdata-sections \
	    -I$(CMSIS_INCLUDE_PATH) \
            -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 $(EXTRA_CFLAGS)
LDFLAGS ?= -Tstm32f411xx.ld -nostartfiles -nostdlib --specs nano.specs -lc -lgcc -Wl,--gc-sections -Wl,-Map=$@.map

USB ?= 0

BUILD := build
SRC := src
INC := inc
TARGET := $(BUILD)/firmware

SOURCES := $(shell find $(SRC) -name '*.c')
OBJECTS := $(SOURCES:$(SRC)/%.c=$(BUILD)/%.o)

.PHONY: build dump clean emu gdb disasm debug io emu_install addr dbc

build: $(TARGET).bin

$(TARGET).bin: $(TARGET).elf
	$(OBJCOPY) -O binary $< $@

$(TARGET).elf: $(OBJECTS)
	$(CC) $^ $(CFLAGS) -I$(INC) -o $@ $(LDFLAGS)

$(BUILD)/%.o : $(SRC)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I$(INC) -c $< -o $@

flash: $(TARGET).bin
	st-flash --reset write $< 0x8000000

dump: $(TARGET).elf
	$(OBJDUMP) -dh $<

gdb: $(TARGET).elf
	# st-util &> /dev/null &
	$(GDB) $< -iex "target extended-remote localhost:4242" --tui

io:
	tio /dev/ttyUSB$(USB) -b 9600 -m ONLCRNL

debug:
	tio /dev/ttyUSB$(USB) -b 9600

disasm: $(TARGET).elf
	$(GDB) -q $< -ex "set pagination off" -ex "disas /s $(SYMBOL)" -ex quit

addr: $(TARGET).elf
	@readelf $<  -s | awk '/$(SYMBOL)/ { printf("%x ", strtonum("0x"$$2) - 1); printf("%x\n", (strtonum("0x"$$2) + $$3 - 1)) }'

dbc: $(TARGET).elf
	@make --no-print-directory SYMBOL=DBC_fault_handler addr

emu: $(TARGET).bin
	venv/bin/python3 -m emu $<

emu-grammar: $(TARGET).bin
	venv/bin/python3 -m emu -g $<

fuzz: $(TARGET).bin
	@mkdir -p fuzz_outputs
	AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 afl-fuzz -U -i raw_fuzz_inputs -o fuzz_outputs venv/bin/python3 -m emu $< -i @@

fuzz-grammar: $(TARGET).bin
	@mkdir -p fuzz_outputs
	export AFL_SKIP_CPUFREQ=1
	export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
	afl-fuzz -U -i grammar_fuzz_inputs -o fuzz_outputs venv/bin/python3 -m emu $< -g -i @@

emu_install: venv

venv: requirements.txt
	python3 -m venv venv
	venv/bin/pip3 install -r requirements.txt

clean:
	rm -rf build
