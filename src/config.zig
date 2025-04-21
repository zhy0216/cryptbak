const std = @import("std");
const Allocator = std.mem.Allocator;

// Add a debug flag - will be true in debug mode, false in release modes
pub const enable_debug_output = std.debug.runtime_safety;

// Helper function for debug prints
pub fn debugPrint(comptime fmt: []const u8, args: anytype) void {
    if (enable_debug_output) {
        std.debug.print(fmt, args);
    }
}

pub const Mode = enum {
    Encrypt,
    Decrypt,
};

pub const Config = struct {
    source_dir: []const u8,
    output_dir: []const u8,
    password: []const u8,
    mode: Mode,
    watch_mode: bool,
    min_backup_period: u64, // in seconds
};

pub fn parseArgs(allocator: Allocator) !Config {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 4) {
        std.debug.print("Usage: ./cryptbak source_folder output_folder [-d] [-t] -p password\n", .{});
        std.debug.print("  -d        Decrypt mode (default is encrypt)\n", .{});
        std.debug.print("  -t        Watch mode: continuously monitor source folder for changes\n", .{});
        std.debug.print("  -p pass   Password for encryption/decryption\n", .{});
        return error.InvalidArguments;
    }

    var config = Config{
        .source_dir = try allocator.dupe(u8, args[1]),
        .output_dir = try allocator.dupe(u8, args[2]),
        .password = "",
        .mode = .Encrypt,
        .watch_mode = false,
        .min_backup_period = 90, // Default 90 seconds
    };

    var i: usize = 3;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-d")) {
            config.mode = .Decrypt;
        } else if (std.mem.eql(u8, arg, "-t")) {
            config.watch_mode = true;
        } else if (std.mem.eql(u8, arg, "-p")) {
            if (i + 1 >= args.len) {
                return error.MissingPassword;
            }
            config.password = try allocator.dupe(u8, args[i + 1]);
            i += 1;
        }
    }

    if (config.password.len == 0) {
        return error.MissingPassword;
    }

    return config;
}

pub fn freeConfig(allocator: Allocator, config: Config) void {
    allocator.free(config.source_dir);
    allocator.free(config.output_dir);
    allocator.free(config.password);
}
