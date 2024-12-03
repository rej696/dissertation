
PREFIX ?= arm-none-eabi
CC = $(PREFIX)-gcc
OBJCOPY = $(PREFIX)-objcopy
OBJDUMP = $(PREFIX)-objdump
GDB ?= $(PREFIX)-gdb
PYTHON ?= python

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

.PHONY: build dump clean emu emu-raw emu-bb gdb disasm debug io emu_install addr dbc

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

emu-raw: $(TARGET).bin
	venv/bin/python3 -m emu $<

emu: $(TARGET).bin
	venv/bin/python3 -m emu -g $<

emu-bb-raw: $(TARGET).bin
	venv/bin/python3 -m emu -b $<

emu-bb: $(TARGET).bin
	venv/bin/python3 -m emu -b -g $<

fuzz-raw: $(TARGET).bin
	AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_AUTORESUME=1 afl-fuzz -U -t +50000 -i raw_fuzz_inputs -o raw_fuzz_outputs $(FUZZER_NAME) $(PYTHON) -m emu $< -i @@F

fuzz-raw-debug: $(TARGET).bin
	AFL_DEBUG=1 AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_AUTORESUME=1 afl-fuzz -U -t +50000 -i raw_fuzz_inputs -o raw_fuzz_outputs $(PYTHON) -m emu $< -i @@F

fuzz: $(TARGET).bin
	AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_AUTORESUME=1 afl-fuzz -U -t +50000 -i grammar_fuzz_inputs -o grammar_fuzz_outputs $(FUZZER_NAME) $(PYTHON) -m emu $< -g -i @@

fuzz-debug: $(TARGET).bin
	AFL_DEBUG=1 AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_AUTORESUME=1 afl-fuzz -U -t +50000 -i grammar_fuzz_inputs -o grammar_fuzz_outputs $(FUZZER_NAME) $(PYTHON) -m emu $< -g -i @@

emu_install: venv

venv: requirements.txt
	python3 -m venv venv
	venv/bin/pip3 install -r requirements.txt

clean:
	rm -rf build

.PHONY: docker-build docker-fuzz docker-bash docker-logs docker-attach docker-stop chown docker-rm
docker-build:
	docker build -t rej696/afl:latest .

# C-p C-q will background a running docker process
docker-fuzz:
	docker run --rm -it -d --name fuzzer01 -v $$(pwd):/src rej696/afl bash -c "make PYTHON=python3 FUZZER_NAME='-M fuzzer01' fuzz"
	docker run --rm -it -d --name fuzzer02 -v $$(pwd):/src rej696/afl bash -c "make PYTHON=python3 FUZZER_NAME='-S fuzzer02' fuzz"

docker-fuzz-secondary:
	docker run --rm -it -d --name fuzzer03 -v $$(pwd):/src rej696/afl bash -c "make PYTHON=python3 FUZZER_NAME='-S fuzzer03' fuzz"
	docker run --rm -it -d --name fuzzer04 -v $$(pwd):/src rej696/afl bash -c "make PYTHON=python3 FUZZER_NAME='-S fuzzer04' fuzz"

docker-bash:
	docker run --rm -it --name fuzz -v $$(pwd):/src rej696/afl bash

docker-logs:
	docker logs fuzz -f

docker-attach:
	docker attach fuzz

docker-stop:
	@make --no-print-directory chown
	docker stop fuzz

chown:
	sudo chown -R $$USER:$$USER -- $(DIR);

docker-rm:
	@make --no-print-directory chown
	docker rm fuzz
