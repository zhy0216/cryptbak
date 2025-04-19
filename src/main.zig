const std = @import("std");
const fs = std.fs;
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const StringHashMap = std.StringHashMap;
const time = std.time;

// Add a debug flag - will be true in debug mode, false in release modes
const enable_debug_output = std.debug.runtime_safety;

// Helper function for debug prints
fn debugPrint(comptime fmt: []const u8, args: anytype) void {
    if (enable_debug_output) {
        std.debug.print(fmt, args);
    }
}

const FileMetadata = struct {
    path: []const u8,
    last_modified: i128,
    size: u64,
    hash: [32]u8, // SHA-256 hash
    is_directory: bool = false, // Flag to indicate this is a directory
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

fn encryptFile(source_path: []const u8, dest_path: []const u8, key: [32]u8, nonce: [12]u8) !void {
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

        crypto.stream.chacha.ChaCha20IETF.xor(encrypted_buffer[0..bytes_read], buffer[0..bytes_read], counter, key, nonce);

        counter += 1;
        try dest_file.writeAll(encrypted_buffer[0..bytes_read]);
    }
}

fn decryptFile(source_path: []const u8, dest_path: []const u8, key: [32]u8) !void {
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

        crypto.stream.chacha.ChaCha20IETF.xor(decrypted_buffer[0..bytes_read], buffer[0..bytes_read], counter, key, nonce);

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

    // Write the salt value for later decryption
    var salt: [16]u8 = undefined;
    std.crypto.random.bytes(&salt);
    try file.writeAll(&salt);

    debugPrint("SaveMetadata: Salt bytes = [ ", .{});
    if (enable_debug_output) {
        for (salt) |b| {
            std.debug.print("{d} ", .{b});
        }
    }
    debugPrint("]\n", .{});

    // Add metadata marker for validation
    const METADATA_MARKER = [_]u8{ 'C', 'R', 'Y', 'P', 'T', 'B', 'A', 'K' };
    try file.writeAll(&METADATA_MARKER);

    // Write unencrypted version, timestamp, and file count
    var header_buf: [20]u8 = undefined; // 4(version) + 8(timestamp) + 8(files_count)
    std.mem.writeInt(u32, header_buf[0..4], metadata.version, .little);
    std.mem.writeInt(i64, header_buf[4..12], metadata.timestamp, .little);
    std.mem.writeInt(u64, header_buf[12..20], metadata.files.items.len, .little);
    try file.writeAll(&header_buf);

    debugPrint("SaveMetadata: Version = {d}\n", .{metadata.version});
    debugPrint("SaveMetadata: Timestamp = {d}\n", .{metadata.timestamp});
    debugPrint("SaveMetadata: Files count = {d}\n", .{metadata.files.items.len});

    // Write nonce
    try file.writeAll(&nonce);

    debugPrint("SaveMetadata: Nonce bytes = [ ", .{});
    if (enable_debug_output) {
        for (nonce) |b| {
            std.debug.print("{d} ", .{b});
        }
    }
    debugPrint("]\n", .{});

    // If there are no files, do not encrypt and write file details
    if (metadata.files.items.len == 0) {
        return;
    }

    // Derive a new key for encryption using the salt
    var enc_key: [32]u8 = undefined;
    try deriveCipherKey(key[0..], salt, &enc_key);

    // Serialize metadata file details section
    var buffer = ArrayList(u8).init(allocator);
    defer buffer.deinit();

    const writer = buffer.writer();

    // File details section does not include version, timestamp, and file count
    for (metadata.files.items) |file_meta| {
        try writer.writeInt(u64, file_meta.path.len, .little);
        try writer.writeAll(file_meta.path);
        try writer.writeInt(i128, file_meta.last_modified, .little);
        try writer.writeInt(u64, file_meta.size, .little);
        try writer.writeAll(&file_meta.hash);
        // Write is_directory as a single byte
        try writer.writeByte(if (file_meta.is_directory) 1 else 0);
    }

    // Print the first bytes to encrypt for debugging
    debugPrint("SaveMetadata: First bytes to encrypt = [ ", .{});
    const max_print = @min(32, buffer.items.len);
    for (buffer.items[0..max_print]) |b| {
        std.debug.print("{d} ", .{b});
    }
    debugPrint("]\n", .{});

    // Encrypt and write the metadata
    const encrypted_buffer = try allocator.alloc(u8, buffer.items.len);
    defer allocator.free(encrypted_buffer);

    // Use a fixed counter value
    const counter: u32 = 0;
    debugPrint("SaveMetadata: Encrypting with counter = {d}\n", .{counter});

    crypto.stream.chacha.ChaCha20IETF.xor(encrypted_buffer, buffer.items, counter, enc_key, nonce);

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

    // Read salt
    var salt: [16]u8 = undefined;
    const salt_read = try file.read(&salt);
    if (salt_read != salt.len) {
        return error.InvalidMetadataFile;
    }

    debugPrint("Metadata: Salt bytes = [ ", .{});
    if (enable_debug_output) {
        for (salt) |b| {
            std.debug.print("{d} ", .{b});
        }
    }
    debugPrint("]\n", .{});

    // Read metadata marker
    var marker: [8]u8 = undefined;
    const marker_read = try file.read(&marker);
    if (marker_read != marker.len) {
        return error.InvalidMetadataFile;
    }

    const expected_marker = [_]u8{ 'C', 'R', 'Y', 'P', 'T', 'B', 'A', 'K' };
    if (!std.mem.eql(u8, &marker, &expected_marker)) {
        std.debug.print("Invalid metadata header marker\n", .{});
        return error.InvalidMetadataFile;
    }
    debugPrint("Metadata: Valid header marker found\n", .{});

    // Read unencrypted metadata header
    var header_buf: [20]u8 = undefined;
    const header_read = try file.read(&header_buf);
    if (header_read != header_buf.len) {
        return error.InvalidMetadataFile;
    }

    // Parse metadata basic information
    const version = std.mem.readInt(u32, header_buf[0..4], .little);
    const timestamp = std.mem.readInt(i64, header_buf[4..12], .little);
    const files_count = std.mem.readInt(u64, header_buf[12..20], .little);

    debugPrint("Metadata: Version = {d}\n", .{version});
    debugPrint("Metadata: Timestamp = {d}\n", .{timestamp});
    debugPrint("Metadata: Files count = {d}\n", .{files_count});

    // Check if the file count is reasonable
    if (files_count > 100000) {
        std.debug.print("Metadata: Files count too large: {d}\n", .{files_count});
        return error.InvalidMetadataFile;
    }

    // Create metadata structure
    var metadata = BackupMetadata.init(allocator);
    metadata.version = version;
    metadata.timestamp = timestamp;

    // If there are no files, return directly
    if (files_count == 0) {
        return metadata;
    }

    // Read nonce
    var nonce: [12]u8 = undefined;
    const nonce_read = try file.read(&nonce);
    if (nonce_read != nonce.len) {
        return error.InvalidMetadataFile;
    }

    debugPrint("Metadata: Nonce bytes = [ ", .{});
    if (enable_debug_output) {
        for (nonce) |b| {
            std.debug.print("{d} ", .{b});
        }
    }
    debugPrint("]\n", .{});

    // Derive a new key for decryption using the salt
    var dec_key: [32]u8 = undefined;
    try deriveCipherKey(key[0..], salt, &dec_key);

    // Read the rest of the file
    const stat = try file.stat();
    // Calculate the size of the encrypted data section = total file size - header size
    // Header includes: salt(16) + marker(8) + header_buf(20) + nonce(12)
    const header_size = salt.len + marker.len + header_buf.len + nonce.len;
    const encrypted_size = stat.size - header_size;

    debugPrint("Metadata: File total size = {d}, header size = {d}, encrypted size = {d}\n", .{ stat.size, header_size, encrypted_size });

    if (encrypted_size <= 0) {
        debugPrint("Metadata: No encrypted data\n", .{});
        return metadata;
    }

    // Pre-allocate enough capacity for the ArrayList
    try metadata.files.ensureTotalCapacity(files_count);

    const encrypted_buffer = try allocator.alloc(u8, encrypted_size);
    defer allocator.free(encrypted_buffer);

    const bytes_read = try file.read(encrypted_buffer);
    if (bytes_read != encrypted_size) {
        debugPrint("Metadata: Failed to read encrypted data. Expected {d} bytes, got {d}\n", .{ encrypted_size, bytes_read });
        return error.InvalidMetadataFile;
    }

    // Decrypt the data
    const decrypted_buffer = try allocator.alloc(u8, encrypted_size);
    defer allocator.free(decrypted_buffer);

    // Use the same counter value as for encryption
    const counter: u32 = 0;
    debugPrint("LoadMetadata: Decrypting with counter = {d}\n", .{counter});

    crypto.stream.chacha.ChaCha20IETF.xor(decrypted_buffer, encrypted_buffer, counter, dec_key, nonce);

    // Print the first bytes of the decrypted data for debugging
    debugPrint("LoadMetadata: First bytes of decrypted data = [ ", .{});
    const max_print = @min(32, decrypted_buffer.len);
    for (decrypted_buffer[0..max_print]) |b| {
        std.debug.print("{d} ", .{b});
    }
    debugPrint("]\n", .{});

    // Deserialize
    var stream = std.io.fixedBufferStream(decrypted_buffer);
    const reader = stream.reader();

    // Read and add all file metadata
    for (0..files_count) |i| {
        var path_len_bytes: [8]u8 = undefined;
        const path_len_read = reader.read(&path_len_bytes) catch |err| {
            debugPrint("Error reading path_len for file {d}: {any}\n", .{ i, err });
            return error.InvalidMetadataFile;
        };

        if (path_len_read != path_len_bytes.len) {
            debugPrint("Incomplete path_len read for file {d}: got {d} bytes\n", .{ i, path_len_read });
            return error.InvalidMetadataFile;
        }

        const path_len = std.mem.readInt(u64, &path_len_bytes, .little);
        debugPrint("LoadMetadata: File {d} path length = {d}\n", .{ i, path_len });

        // Add a maximum path length limit to prevent memory allocation issues
        const MAX_PATH_LEN: u64 = 1024;
        if (path_len == 0 or path_len > MAX_PATH_LEN) {
            debugPrint("Invalid path length {d} for file {d}\n", .{ path_len, i });
            return error.InvalidMetadataFile;
        }

        const path = allocator.alloc(u8, path_len) catch |err| {
            debugPrint("Failed to allocate memory for path: {any}\n", .{err});
            return error.InvalidMetadataFile;
        };
        errdefer allocator.free(path);

        const path_read = reader.read(path) catch |err| {
            debugPrint("Error reading path data: {any}\n", .{err});
            allocator.free(path);
            return error.InvalidMetadataFile;
        };

        if (path_read != path_len) {
            debugPrint("Incomplete path read for file {d}: got {d} of {d} bytes\n", .{ i, path_read, path_len });
            allocator.free(path);
            return error.InvalidMetadataFile;
        }

        var last_modified_bytes: [16]u8 = undefined;
        const last_mod_read = reader.read(&last_modified_bytes) catch |err| {
            debugPrint("Error reading last_modified: {any}\n", .{err});
            allocator.free(path);
            return error.InvalidMetadataFile;
        };

        if (last_mod_read != last_modified_bytes.len) {
            debugPrint("Incomplete last_modified read for file {d}\n", .{i});
            allocator.free(path);
            return error.InvalidMetadataFile;
        }

        const last_modified = std.mem.readInt(i128, &last_modified_bytes, .little);

        var size_bytes: [8]u8 = undefined;
        const size_read = reader.read(&size_bytes) catch |err| {
            debugPrint("Error reading size: {any}\n", .{err});
            allocator.free(path);
            return error.InvalidMetadataFile;
        };

        if (size_read != size_bytes.len) {
            debugPrint("Incomplete size read for file {d}\n", .{i});
            allocator.free(path);
            return error.InvalidMetadataFile;
        }

        const size = std.mem.readInt(u64, &size_bytes, .little);

        var hash: [32]u8 = undefined;
        const hash_read = reader.read(&hash) catch |err| {
            debugPrint("Error reading hash for file {d}: {any}\n", .{ i, err });
            allocator.free(path);
            return error.InvalidMetadataFile;
        };

        if (hash_read != hash.len) {
            debugPrint("Incomplete hash read for file {d}: got {d} bytes\n", .{ i, hash_read });
            allocator.free(path);
            return error.InvalidMetadataFile;
        }

        // Read is_directory flag (single byte)
        var is_directory_byte: [1]u8 = undefined;
        const is_directory_read = reader.read(&is_directory_byte) catch |err| {
            debugPrint("Error reading is_directory flag: {any}\n", .{err});
            allocator.free(path);
            return error.InvalidMetadataFile;
        };

        // Ensure we read the complete byte
        if (is_directory_read != 1) {
            debugPrint("Incomplete is_directory flag read: got {d} bytes\n", .{is_directory_read});
            allocator.free(path);
            return error.InvalidMetadataFile;
        }

        // Convert byte to boolean
        const is_directory = (is_directory_byte[0] != 0);

        metadata.files.append(FileMetadata{
            .path = path,
            .last_modified = last_modified,
            .size = size,
            .hash = hash,
            .is_directory = is_directory,
        }) catch |err| {
            debugPrint("Failed to append file metadata: {any}\n", .{err});
            allocator.free(path);
            return error.InvalidMetadataFile;
        };
    }

    // Check if the read file count matches the expected count
    if (metadata.files.items.len != files_count) {
        debugPrint("File count mismatch: expected {d}, got {d}\n", .{ files_count, metadata.files.items.len });
        return error.InvalidMetadataFile;
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

fn scanDirectory(allocator: Allocator, dir_path: []const u8, base_path: []const u8, file_list: *ArrayList(FileMetadata)) !void {
    var dir = try fs.cwd().openDir(dir_path, .{ .iterate = true });
    defer dir.close();

    // Check if the current directory is empty
    var is_current_dir_empty = true;

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        is_current_dir_empty = false; // If there's at least one entry, it's not an empty directory

        const full_path = try fs.path.join(allocator, &[_][]const u8{ dir_path, entry.name });
        defer allocator.free(full_path);

        if (entry.kind == .directory) {
            // Check if the subdirectory is empty
            var is_empty = true;
            {
                var sub_dir = try fs.cwd().openDir(full_path, .{ .iterate = true });
                defer sub_dir.close();

                var sub_iter = sub_dir.iterate();
                if (try sub_iter.next()) |_| {
                    is_empty = false;
                }
            }

            // Get the relative path
            const rel_path = try fs.path.relative(allocator, base_path, full_path);
            defer allocator.free(rel_path);

            // If the subdirectory is empty, add it to the file list as a directory
            if (is_empty) {
                const rel_path_dup = try allocator.dupe(u8, rel_path);

                try file_list.append(FileMetadata{
                    .path = rel_path_dup,
                    .last_modified = 0, // Not important for directories
                    .size = 0,
                    .hash = [_]u8{0} ** 32, // Empty hash for directories
                    .is_directory = true,
                });
            }

            try scanDirectory(allocator, full_path, base_path, file_list);
        } else {
            const rel_path = try fs.path.relative(allocator, base_path, full_path);
            defer allocator.free(rel_path);

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
                .is_directory = false,
            });
        }
    }

    // If the current directory is empty and not the base directory itself, add it as an empty directory
    if (is_current_dir_empty and !std.mem.eql(u8, dir_path, base_path)) {
        const rel_path = try fs.path.relative(allocator, base_path, dir_path);
        defer allocator.free(rel_path);

        const rel_path_dup = try allocator.dupe(u8, rel_path);

        try file_list.append(FileMetadata{
            .path = rel_path_dup,
            .last_modified = 0,
            .size = 0,
            .hash = [_]u8{0} ** 32,
            .is_directory = true,
        });
    }
}

fn processBackup(allocator: Allocator, config: Config, key: [32]u8, existing_metadata: BackupMetadata) !void {
    // Scan source directory
    var current_files = ArrayList(FileMetadata).init(allocator);
    defer {
        // Do not free the paths here, as their ownership has been transferred to new_metadata
        current_files.clearRetainingCapacity();
        current_files.deinit(); // Deallocate the ArrayList itself
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

        // If it's a directory, just create the directory
        if (file.is_directory) {
            debugPrint("Creating empty directory: {s}\n", .{file.path});
            try fs.cwd().makePath(dest_path);
            try new_metadata.files.append(file);
            continue;
        }

        const existing_entry = existing_files_map.get(file.path);
        const needs_backup = if (existing_entry) |entry|
            !std.mem.eql(u8, &entry.hash, &file.hash)
        else
            true;

        if (needs_backup) {
            // Ensure parent directories exist
            const dest_dir = fs.path.dirname(dest_path) orelse "";
            if (dest_dir.len > 0) {
                try fs.cwd().makePath(dest_dir);
            }

            std.debug.print("Encrypting file: {s}\n", .{file.path});
            var nonce: [12]u8 = undefined;
            std.crypto.random.bytes(&nonce);

            const enc_key = key;

            try encryptFile(source_path, dest_path, enc_key, nonce);
        } else {
            debugPrint("File unchanged, skipping: {s}\n", .{file.path});
        }

        // The file path's ownership is now transferred to new_metadata, so do not free it here
        try new_metadata.files.append(file);
    }

    // Identify files to remove (in backup but not in source)
    var files_to_remove = ArrayList([]const u8).init(allocator);
    defer {
        for (files_to_remove.items) |path| {
            allocator.free(path);
        }
        files_to_remove.deinit();
    }

    var existing_iter = existing_files_map.iterator();
    while (existing_iter.next()) |entry| {
        const existing_key = entry.key_ptr.*;
        var found = false;

        for (new_metadata.files.items) |current| {
            if (std.mem.eql(u8, current.path, existing_key)) {
                found = true;
                break;
            }
        }

        if (!found) {
            const path_copy = try allocator.dupe(u8, existing_key);
            try files_to_remove.append(path_copy);
        }
    }

    for (files_to_remove.items) |file| {
        const full_path = try fs.path.join(allocator, &[_][]const u8{ config.output_dir, file });
        defer allocator.free(full_path);

        debugPrint("Removing deleted file: {s}\n", .{file});
        fs.cwd().deleteFile(full_path) catch |err| {
            debugPrint("Warning: Could not delete {s}: {any}\n", .{ full_path, err });
        };
    }

    // Save new metadata
    try saveMetadata(allocator, new_metadata, config.output_dir, key);
    debugPrint("Backup completed successfully!\n", .{});
}

fn doDecrypt(allocator: Allocator, config: Config) !void {
    debugPrint("Decrypting {s} to {s}\n", .{ config.source_dir, config.output_dir });

    // Ensure output directory exists
    try fs.cwd().makePath(config.output_dir);

    // Convert password to key (use deriveCipherKey instead of direct copy)
    var key: [32]u8 = undefined;
    var initial_salt: [16]u8 = undefined;
    @memset(&initial_salt, 0); // Use all-zero salt for initialization
    try deriveCipherKey(config.password, initial_salt, &key);

    // Load metadata
    var metadata = try loadMetadata(allocator, config.source_dir, key);
    defer metadata.deinit();

    // Process each file in the metadata
    for (metadata.files.items) |file| {
        const source_path = try fs.path.join(allocator, &[_][]const u8{ config.source_dir, file.path });
        defer allocator.free(source_path);

        const dest_path = try fs.path.join(allocator, &[_][]const u8{ config.output_dir, file.path });
        defer allocator.free(dest_path);

        // If it's a directory, just create the directory
        if (file.is_directory) {
            debugPrint("Creating empty directory: {s}\n", .{file.path});
            try fs.cwd().makePath(dest_path);
            continue;
        }

        // Ensure parent directories exist
        const dest_dir = fs.path.dirname(dest_path) orelse "";
        if (dest_dir.len > 0) {
            try fs.cwd().makePath(dest_dir);
        }

        const dec_key = key;

        try decryptFile(source_path, dest_path, dec_key);
    }

    debugPrint("Decryption completed successfully!\n", .{});
}

fn doEncrypt(allocator: Allocator, config: Config) !void {
    debugPrint("Encrypting {s} to {s}\n", .{ config.source_dir, config.output_dir });

    // Ensure output directory exists
    try fs.cwd().makePath(config.output_dir);

    // Use all-zero initial salt for key derivation, matching doDecrypt
    var initial_salt: [16]u8 = undefined;
    @memset(&initial_salt, 0); // Use all-zero salt for initialization
    var key: [32]u8 = undefined;
    try deriveCipherKey(config.password, initial_salt, &key);

    // Try to load existing metadata
    var empty_metadata = BackupMetadata.init(allocator);
    defer empty_metadata.deinit();

    var existing_metadata = loadMetadata(allocator, config.output_dir, key) catch |err| {
        if (err == error.FileNotFound) {
            // If no metadata exists, return an empty one
            return processBackup(allocator, config, key, empty_metadata);
        }
        return err;
    };
    defer existing_metadata.deinit();

    return processBackup(allocator, config, key, existing_metadata);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = parseArgs(allocator) catch |err| {
        debugPrint("Error parsing arguments: {any}\n", .{err});
        return;
    };
    defer freeConfig(allocator, config);

    switch (config.mode) {
        .Encrypt => try doEncrypt(allocator, config),
        .Decrypt => try doDecrypt(allocator, config),
    }
}
