pub const Bank = enum(u16) {
    A = 0,
    B = 1,
    C = 2,

    pub fn pin(self: Bank, num: u8) u16 {
        return @intFromEnum(self) << 8 | num;
    }

    pub fn bankFromPin(x: comptime_int) Bank {
        return @enumFromInt(x >> 8);
    }
};

pub fn bit(x: comptime_int) comptime_int {
    return 1 << x;
}

pub fn pinNum(pin: comptime_int) comptime_int {
    return pin & 0xFF;
}
