const c = @cImport({
    @cInclude("hal/uart.h");
});

pub const Uart = enum(c_uint) {
    uart1 = c.UART1,
    uart2 = c.UART2,
    uart6 = c.UART6,

    pub fn init(self: Uart, baud: u32) void {
        c.uart_init(@intFromEnum(self), baud);
    }

    pub fn readReady(self: Uart) bool {
        return c.uart_read_ready(@intFromEnum(self));
    }

    pub fn readByte(self: Uart) u8 {
        return c.uart_read_byte(@intFromEnum(self));
    }

    pub fn writeByte(self: Uart, byte: u8) void {
        c.uart_write_byte(@intFromEnum(self), byte);
    }

    pub fn write(self: Uart, buf: []const u8) void {
        const cbuf: [*c]const u8 = buf.ptr;
        const csize = buf.len;

        c.uart_write_buf(@intFromEnum(self), csize, cbuf);
    }

    pub fn writeCStr(self: Uart, str: [*:0]const u8) void {
        const cstr: [*c]const u8 = str;
        c.uart_write_str(@intFromEnum(self), cstr);
    }
};
