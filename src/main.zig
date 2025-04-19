const std = @import("std");

const config = @import("config.zig");
const backup = @import("backup.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const conf = config.parseArgs(allocator) catch |err| {
        config.debugPrint("Error parsing arguments: {any}\n", .{err});
        return;
    };
    defer config.freeConfig(allocator, conf);

    switch (conf.mode) {
        .Encrypt => try backup.doEncrypt(allocator, conf),
        .Decrypt => try backup.doDecrypt(allocator, conf),
    }
}
