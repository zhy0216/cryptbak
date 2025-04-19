const std = @import("std");
const fs = std.fs;
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const StringHashMap = std.StringHashMap;
const time = std.time;

const FileMetadata = struct {
    path: []const u8,
    last_modified: i128,
    size: u64,
    hash: [32]u8, // SHA-256 hash
};

const BackupMetadata = struct {
    version: u32 = 1,
    timestamp: i64,
    files: ArrayList(FileMetadata),
    
    pub fn init(allocator: Allocator) BackupMetadata {
        return BackupMetadata{
            .timestamp = time.milliTimestamp(),
            .files = ArrayList(FileMetadata).init(allocator),
        };
    }
    
    pub fn deinit(self: *BackupMetadata) void {
        for (self.files.items) |file| {
            self.files.allocator.free(file.path);
        }
        self.files.deinit();
    }
};

const Mode = enum {
    Encrypt,
    Decrypt,
};

const Config = struct {
    source_dir: []const u8,
    output_dir: []const u8,
    password: []const u8,
    mode: Mode,
};

fn parseArgs(allocator: Allocator) !Config {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    
    if (args.len < 4) {
        std.debug.print("Usage: ./cryptbak source_folder output_folder [-d] -p password\n", .{});
        std.debug.print("  -d        Decrypt mode (default is encrypt)\n", .{});
        std.debug.print("  -p pass   Password for encryption/decryption\n", .{});
        return error.InvalidArguments;
    }
    
    var config = Config{
        .source_dir = try allocator.dupe(u8, args[1]),
        .output_dir = try allocator.dupe(u8, args[2]),
        .password = "",
        .mode = .Encrypt,
    };
    
    var i: usize = 3;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-d")) {
            config.mode = .Decrypt;
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

fn freeConfig(allocator: Allocator, config: Config) void {
    allocator.free(config.source_dir);
    allocator.free(config.output_dir);
    allocator.free(config.password);
}

fn deriveCipherKey(password: []const u8, salt: [16]u8, key: *[32]u8) !void {
    try crypto.pwhash.pbkdf2(key, password, &salt, 100000, crypto.auth.hmac.sha2.HmacSha256);
}

fn generateRandomSalt() [16]u8 {
    var salt: [16]u8 = undefined;
    std.crypto.random.bytes(&salt);
    return salt;
}

fn calculateFileHash(file_path: []const u8) ![32]u8 {
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

fn encryptFile(
    source_path: []const u8, 
    dest_path: []const u8,
    key: [32]u8,
    nonce: [12]u8
) !void {
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
        
        crypto.stream.chacha.ChaCha20IETF.xor(
            encrypted_buffer[0..bytes_read], 
            buffer[0..bytes_read], 
            counter, 
            key, 
            nonce
        );
        
        counter += 1;
        try dest_file.writeAll(encrypted_buffer[0..bytes_read]);
    }
}

fn decryptFile(
    source_path: []const u8, 
    dest_path: []const u8,
    key: [32]u8
) !void {
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
        
        crypto.stream.chacha.ChaCha20IETF.xor(
            decrypted_buffer[0..bytes_read], 
            buffer[0..bytes_read], 
            counter, 
            key, 
            nonce
        );
        
        counter += 1;
        try dest_file.writeAll(decrypted_buffer[0..bytes_read]);
    }
}

fn saveMetadata(allocator: Allocator, metadata: BackupMetadata, output_dir: []const u8, key: [32]u8) !void {
    var nonce = generateRandomSalt()[0..12].*;
    
    const metadata_path = try fs.path.join(allocator, &[_][]const u8{ output_dir, ".cryptbak.meta" });
    defer allocator.free(metadata_path);
    
    var file = try fs.cwd().createFile(metadata_path, .{});
    defer file.close();
    
    // Write nonce
    try file.writeAll(&nonce);
    
    // Serialize metadata
    var buffer = ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    const writer = buffer.writer();
    try writer.writeInt(u32, metadata.version, .little);
    try writer.writeInt(i64, metadata.timestamp, .little);
    try writer.writeInt(u64, metadata.files.items.len, .little);
    
    for (metadata.files.items) |file_meta| {
        try writer.writeInt(u64, file_meta.path.len, .little);
        try writer.writeAll(file_meta.path);
        try writer.writeInt(i128, file_meta.last_modified, .little);
        try writer.writeInt(u64, file_meta.size, .little);
        try writer.writeAll(&file_meta.hash);
    }
    
    // Encrypt and write the metadata
    const encrypted_buffer = try allocator.alloc(u8, buffer.items.len);
    defer allocator.free(encrypted_buffer);
    
    crypto.stream.chacha.ChaCha20IETF.xor(
        encrypted_buffer,
        buffer.items,
        0, // counter
        key,
        nonce
    );
    
    try file.writeAll(encrypted_buffer);
}

fn loadMetadata(allocator: Allocator, output_dir: []const u8, key: [32]u8) !BackupMetadata {
    const metadata_path = try fs.path.join(allocator, &[_][]const u8{ output_dir, ".cryptbak.meta" });
    defer allocator.free(metadata_path);
    
    var file = fs.cwd().openFile(metadata_path, .{}) catch |err| {
        if (err == error.FileNotFound) {
            // If no metadata exists, return an empty one
            return BackupMetadata.init(allocator);
        }
        return err;
    };
    defer file.close();
    
    // Read nonce
    var nonce: [12]u8 = undefined;
    const nonce_read = try file.read(&nonce);
    if (nonce_read != nonce.len) {
        return error.InvalidMetadataFile;
    }
    
    // Read the rest of the file
    const stat = try file.stat();
    const encrypted_size = stat.size - nonce.len;
    if (encrypted_size == 0) {
        return BackupMetadata.init(allocator);
    }
    
    const encrypted_buffer = try allocator.alloc(u8, encrypted_size);
    defer allocator.free(encrypted_buffer);
    
    const bytes_read = try file.read(encrypted_buffer);
    if (bytes_read != encrypted_size) {
        return error.InvalidMetadataFile;
    }
    
    // Decrypt the data
    const decrypted_buffer = try allocator.alloc(u8, encrypted_size);
    defer allocator.free(decrypted_buffer);
    
    crypto.stream.chacha.ChaCha20IETF.xor(
        decrypted_buffer,
        encrypted_buffer,
        0, // counter
        key,
        nonce
    );
    
    // Deserialize
    var metadata = BackupMetadata.init(allocator);
    var stream = std.io.fixedBufferStream(decrypted_buffer);
    const reader = stream.reader();
    
    var version_bytes: [4]u8 = undefined;
    _ = try reader.read(&version_bytes);
    metadata.version = std.mem.readInt(u32, &version_bytes, .little);
    
    var timestamp_bytes: [8]u8 = undefined;
    _ = try reader.read(&timestamp_bytes);
    metadata.timestamp = std.mem.readInt(i64, &timestamp_bytes, .little);
    
    var files_count_bytes: [8]u8 = undefined;
    _ = try reader.read(&files_count_bytes);
    const files_count = std.mem.readInt(u64, &files_count_bytes, .little);
    
    for (0..files_count) |_| {
        var path_len_bytes: [8]u8 = undefined;
        _ = try reader.read(&path_len_bytes);
        const path_len = std.mem.readInt(u64, &path_len_bytes, .little);
        
        const path = try allocator.alloc(u8, path_len);
        _ = try reader.read(path);
        
        var last_modified_bytes: [16]u8 = undefined;
        _ = try reader.read(&last_modified_bytes);
        const last_modified = std.mem.readInt(i128, &last_modified_bytes, .little);
        
        var size_bytes: [8]u8 = undefined;
        _ = try reader.read(&size_bytes);
        const size = std.mem.readInt(u64, &size_bytes, .little);
        
        var hash: [32]u8 = undefined;
        _ = try reader.read(&hash);
        
        try metadata.files.append(FileMetadata{
            .path = path,
            .last_modified = last_modified,
            .size = size,
            .hash = hash,
        });
    }
    
    return metadata;
}

fn getRelativePath(full_path: []const u8, base_path: []const u8) []const u8 {
    if (std.mem.startsWith(u8, full_path, base_path)) {
        var rel_path = full_path[base_path.len..];
        // Skip leading slash if present
        if (rel_path.len > 0 and rel_path[0] == fs.path.sep) {
            rel_path = rel_path[1..];
        }
        return rel_path;
    }
    return full_path;
}

fn scanDirectory(
    allocator: Allocator,
    dir_path: []const u8,
    base_path: []const u8,
    file_list: *ArrayList(FileMetadata)
) !void {
    var dir = try fs.cwd().openDir(dir_path, .{ .iterate = true });
    defer dir.close();
    
    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        const full_path = try fs.path.join(allocator, &[_][]const u8{ dir_path, entry.name });
        defer allocator.free(full_path);
        
        if (entry.kind == .directory) {
            try scanDirectory(allocator, full_path, base_path, file_list);
        } else if (entry.kind == .file) {
            const rel_path = getRelativePath(full_path, base_path);
            const rel_path_dup = try allocator.dupe(u8, rel_path);
            
            const file = try fs.cwd().openFile(full_path, .{});
            const stat = try file.stat();
            file.close();
            
            const hash = try calculateFileHash(full_path);
            
            try file_list.append(FileMetadata{
                .path = rel_path_dup,
                .last_modified = stat.mtime,
                .size = stat.size,
                .hash = hash,
            });
        }
    }
}

fn doEncrypt(allocator: Allocator, config: Config) !void {
    std.debug.print("Encrypting {s} to {s}\n", .{ config.source_dir, config.output_dir });
    
    // Ensure output directory exists
    try fs.cwd().makePath(config.output_dir);
    
    // Derive encryption key from password
    const salt = generateRandomSalt();
    
    var key: [32]u8 = undefined;
    try deriveCipherKey(config.password, salt, &key);
    
    // Try to load existing metadata
    var empty_metadata = BackupMetadata.init(allocator);
    defer empty_metadata.deinit();
    
    var existing_metadata = loadMetadata(allocator, config.output_dir, key) catch |err| {
        if (err == error.FileNotFound) {
            return processBackup(allocator, config, key, empty_metadata);
        }
        return err;
    };
    defer existing_metadata.deinit();
    
    return processBackup(allocator, config, key, existing_metadata);
}

fn processBackup(
    allocator: Allocator, 
    config: Config, 
    key: [32]u8, 
    existing_metadata: BackupMetadata
) !void {
    // Scan source directory
    var current_files = ArrayList(FileMetadata).init(allocator);
    defer {
        for (current_files.items) |file| {
            allocator.free(file.path);
        }
        current_files.deinit();
    }
    
    try scanDirectory(allocator, config.source_dir, config.source_dir, &current_files);
    
    // Create a map for faster lookup of existing files
    var existing_files_map = StringHashMap(FileMetadata).init(allocator);
    defer existing_files_map.deinit();
    
    for (existing_metadata.files.items) |file| {
        try existing_files_map.put(file.path, file);
    }
    
    // Create new metadata
    var new_metadata = BackupMetadata.init(allocator);
    defer new_metadata.deinit();
    
    // Process each file: only encrypt if changed or new
    for (current_files.items) |file| {
        const dest_path = try fs.path.join(allocator, &[_][]const u8{ config.output_dir, file.path });
        defer allocator.free(dest_path);
        
        const source_path = try fs.path.join(allocator, &[_][]const u8{ config.source_dir, file.path });
        defer allocator.free(source_path);
        
        const existing_entry = existing_files_map.get(file.path);
        const needs_backup = if (existing_entry) |entry| 
            !std.mem.eql(u8, &entry.hash, &file.hash)
        else 
            true;
        
        if (needs_backup) {
            std.debug.print("Encrypting file: {s}\n", .{file.path});
            var nonce_bytes = generateRandomSalt();
            var nonce: [12]u8 = undefined;
            std.mem.copyForwards(u8, &nonce, nonce_bytes[0..12]);
            
            try encryptFile(source_path, dest_path, key, nonce);
        } else {
            std.debug.print("File unchanged, skipping: {s}\n", .{file.path});
        }
        
        // Add to new metadata
        const path_copy = try allocator.dupe(u8, file.path);
        try new_metadata.files.append(FileMetadata{
            .path = path_copy,
            .last_modified = file.last_modified,
            .size = file.size,
            .hash = file.hash,
        });
    }
    
    // Find and remove files that no longer exist in source
    var files_to_remove = ArrayList([]const u8).init(allocator);
    defer {
        for (files_to_remove.items) |file| {
            allocator.free(file);
        }
        files_to_remove.deinit();
    }
    
    var iter = existing_files_map.keyIterator();
    while (iter.next()) |existing_key| {
        var found = false;
        for (current_files.items) |file| {
            if (std.mem.eql(u8, file.path, existing_key.*)) {
                found = true;
                break;
            }
        }
        
        if (!found) {
            const path_copy = try allocator.dupe(u8, existing_key.*);
            try files_to_remove.append(path_copy);
        }
    }
    
    for (files_to_remove.items) |file| {
        const full_path = try fs.path.join(allocator, &[_][]const u8{ config.output_dir, file });
        defer allocator.free(full_path);
        
        std.debug.print("Removing deleted file: {s}\n", .{file});
        fs.cwd().deleteFile(full_path) catch |err| {
            std.debug.print("Warning: Could not delete {s}: {any}\n", .{ full_path, err });
        };
    }
    
    // Save new metadata
    try saveMetadata(allocator, new_metadata, config.output_dir, key);
    std.debug.print("Backup completed successfully!\n", .{});
}

fn doDecrypt(allocator: Allocator, config: Config) !void {
    std.debug.print("Decrypting {s} to {s}\n", .{ config.source_dir, config.output_dir });
    
    // Ensure output directory exists
    try fs.cwd().makePath(config.output_dir);
    
    // Derive decryption key from password
    var salt: [16]u8 = undefined;
    for (0..salt.len) |i| {
        salt[i] = 0; // Use a fixed salt for now
    }
    
    var key: [32]u8 = undefined;
    try deriveCipherKey(config.password, salt, &key);
    
    // Load metadata
    var metadata = try loadMetadata(allocator, config.source_dir, key);
    defer metadata.deinit();
    
    // Process each file in the metadata
    for (metadata.files.items) |file| {
        const source_path = try fs.path.join(allocator, &[_][]const u8{ config.source_dir, file.path });
        defer allocator.free(source_path);
        
        const dest_path = try fs.path.join(allocator, &[_][]const u8{ config.output_dir, file.path });
        defer allocator.free(dest_path);
        
        std.debug.print("Decrypting file: {s}\n", .{file.path});
        try decryptFile(source_path, dest_path, key);
    }
    
    std.debug.print("Decryption completed successfully!\n", .{});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const config = parseArgs(allocator) catch |err| {
        std.debug.print("Error parsing arguments: {any}\n", .{err});
        return;
    };
    defer freeConfig(allocator, config);
    
    switch (config.mode) {
        .Encrypt => try doEncrypt(allocator, config),
        .Decrypt => try doDecrypt(allocator, config),
    }
}
