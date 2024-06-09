const c = @cImport({
    @cInclude("hal/gpio.h");
    @cInclude("hal/systick.h");
    @cInclude("hal/uart.h");
});

const Bank = enum(u16) {
    A = 0,
    B = 1,
    C = 2,

    pub fn pin(self: Bank, num: u8) u16 {
        const value: u16 = @intFromEnum(self) << 8;
        return value | num;
    }
};

/// TODO make comptime?
// fn pin(bank: Bank, num: u8) u16 {
//     const result: u16 = bank - 'A'
//     return (((bank - 'A') as u8) << 8) | num;
// }

export fn main() c_int {
    const led: u16 = Bank.C.pin(13);
    c.gpio_set_mode(led, c.GPIO_MODE_OUTPUT);

    c.systick_init(c.CLOCK_FREQ / 1000);

    var timer: u32 = 0;
    const period: u32 = 500;
    c.uart_init(c.UART1, 9600);
    var on: bool = true;

    while (true) {
        if (c.systick_timer_expired(&timer, period, c.systick_get_ticks())) {
            c.gpio_write(led, on);
            on = !on;
            c.uart_write_str(c.UART1, if (on) "tick\r\n" else "tock\r\n");
        }
    }

    return 0;
}
