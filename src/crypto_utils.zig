const std = @import("std");
const crypto = std.crypto;
const fs = std.fs;

const config = @import("config.zig");
const debugPrint = config.debugPrint;

pub fn deriveCipherKey(password: []const u8, salt: [16]u8, key: *[32]u8) !void {
    try crypto.pwhash.pbkdf2(key, password, &salt, 100000, crypto.auth.hmac.sha2.HmacSha256);
}

pub fn generateRandomSalt() [16]u8 {
    var salt: [16]u8 = undefined;
    std.crypto.random.bytes(&salt);
    return salt;
}

pub fn calculateFileHash(file_path: []const u8) ![32]u8 {
    const file = try fs.cwd().openFile(file_path, .{});
    defer file.close();

    var hash = crypto.hash.sha2.Sha256.init(.{});
    var buf: [8192]u8 = undefined;

    while (true) {
        const bytes_read = try file.read(&buf);
        if (bytes_read == 0) break;
        hash.update(buf[0..bytes_read]);
    }

    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}

pub fn encrypt(dst: []u8, src: []const u8, counter: u32, key: [32]u8, nonce: [12]u8) void {
    crypto.stream.chacha.ChaCha20IETF.xor(dst, src, counter, key, nonce);
}

pub fn decrypt(dst: []u8, src: []const u8, counter: u32, key: [32]u8, nonce: [12]u8) void {
    crypto.stream.chacha.ChaCha20IETF.xor(dst, src, counter, key, nonce);
}

pub fn encryptFile(source_path: []const u8, dest_path: []const u8, key: [32]u8, nonce: [12]u8) !void {
    var source_file = try fs.cwd().openFile(source_path, .{});
    defer source_file.close();

    try fs.cwd().makePath(fs.path.dirname(dest_path) orelse "");
    var dest_file = try fs.cwd().createFile(dest_path, .{});
    defer dest_file.close();

    // Write nonce first
    try dest_file.writeAll(&nonce);

    var buffer: [8192]u8 = undefined;
    var encrypted_buffer: [8192]u8 = undefined;
    var counter: u32 = 0;

    while (true) {
        const bytes_read = try source_file.read(&buffer);
        if (bytes_read == 0) break;

        encrypt(encrypted_buffer[0..bytes_read], buffer[0..bytes_read], counter, key, nonce);

        counter += 1;
        try dest_file.writeAll(encrypted_buffer[0..bytes_read]);
    }
}

pub fn decryptFile(source_path: []const u8, dest_path: []const u8, key: [32]u8) !void {
    var source_file = try fs.cwd().openFile(source_path, .{});
    defer source_file.close();

    // Read nonce first
    var nonce: [12]u8 = undefined;
    const nonce_read = try source_file.read(&nonce);
    if (nonce_read != nonce.len) {
        return error.InvalidEncryptedFile;
    }

    try fs.cwd().makePath(fs.path.dirname(dest_path) orelse "");
    var dest_file = try fs.cwd().createFile(dest_path, .{});
    defer dest_file.close();

    var buffer: [8192]u8 = undefined;
    var decrypted_buffer: [8192]u8 = undefined;
    var counter: u32 = 0;

    while (true) {
        const bytes_read = try source_file.read(&buffer);
        if (bytes_read == 0) break;

        decrypt(decrypted_buffer[0..bytes_read], buffer[0..bytes_read], counter, key, nonce);

        counter += 1;
        try dest_file.writeAll(decrypted_buffer[0..bytes_read]);
    }
}

pub fn calculateMd5ForFilename(filename: []const u8) [32]u8 {
    var hash = crypto.hash.Md5.init(.{});
    hash.update(filename);
    
    var digest: [16]u8 = undefined;
    hash.final(&digest);
    
    // Convert to hex string and then to a fixed-size byte array
    var hex_digest: [32]u8 = undefined;
    _ = std.fmt.bufPrint(&hex_digest, "{s}", .{std.fmt.fmtSliceHexLower(&digest)}) catch unreachable;
    
    return hex_digest;
}

pub fn getHashedPath(allocator: std.mem.Allocator, original_path: []const u8) ![]const u8 {
    const md5_hash = calculateMd5ForFilename(original_path);
    return std.fmt.allocPrint(allocator, "{s}", .{md5_hash});
}
