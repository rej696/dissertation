
PREFIX ?= arm-none-eabi
CC ?= $(PREFIX)-gcc
OBJCOPY ?= $(PREFIX)-objcopy
OBJDUMP ?= $(PREFIX)-objdump
GDB ?= $(PREFIX)-gdb

SYMBOL ?= main

CMSIS_INCLUDE_PATH ?= CMSIS/Include

CFLAGS  ?=  -W -Wall -Wextra -Werror -Wundef -Wshadow -Wdouble-promotion \
            -Wformat-truncation -fno-common -Wconversion \
            -g3 -Os -ffunction-sections -fdata-sections \
	    -I$(CMSIS_INCLUDE_PATH) \
            -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 $(EXTRA_CFLAGS)
LDFLAGS ?= -Tstm32f411xx.ld -nostartfiles -nostdlib --specs nano.specs -lc -lgcc -Wl,--gc-sections -Wl,-Map=$@.map

BUILD := build
SRC := src
INC := inc
TARGET := $(BUILD)/firmware

SOURCES := $(shell find $(SRC) -name '*.c')
OBJECTS := $(SOURCES:$(SRC)/%.c=$(BUILD)/%.o)

.PHONY: build dump clean emu gdb disasm

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
	$(GDB) $<

disasm: $(TARGET).elf
	$(GDB) -q $< -ex "set pagination off" -ex "disas /s $(SYMBOL)" -ex quit

emu: $(TARGET).bin emu_install
	. venv/bin/activate; python3 -m emu $<

emu_install: requirements.txt venv
	. venv/bin/activate; pip install -r requirements.txt

venv:
	python3 -m venv venv

clean:
	rm -rf build
