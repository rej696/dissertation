const c = @cImport({
    @cInclude("hal/gpio.h");
});

const Mode = enum(u8) {
    input = 0,
    output = 1,
    af = 2,
    analog = 3,
};

pub fn setMode(pin: u16, mode: Mode) void {
    c.gpio_set_mode(pin, @intFromEnum(mode));
}

pub fn setAltFunc(pin: u16, af: u3) bool {
    return c.gpio_set_af(pin, af);
}

pub fn write(pin: u16, value: bool) void {
    c.gpio_write(pin, value);
}
