const std = @import("std");
const fs = std.fs;
const time = std.time;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const StringHashMap = std.StringHashMap;

const crypto_utils = @import("crypto_utils.zig");
const config = @import("config.zig");
const debugPrint = config.debugPrint;

pub const FileMetadata = struct {
    path: []const u8,
    last_modified: i128,
    size: u64,
    hash: [32]u8, // SHA-256 hash
    is_directory: bool = false, // Flag to indicate this is a directory
};

pub const BackupMetadata = struct {
    version: u32 = 1,
    timestamp: i64,
    files: ArrayList(FileMetadata),
    metadata_nonce: ?[12]u8 = null, // Nonce for ChaCha20 encryption, null if not set
    key_salt: ?[16]u8 = null, // Salt for key derivation, null if not set

    pub fn init(allocator: Allocator) BackupMetadata {
        return BackupMetadata{
            .timestamp = time.milliTimestamp(),
            .files = ArrayList(FileMetadata).init(allocator),
            .metadata_nonce = null,
            .key_salt = null,
        };
    }

    pub fn deinit(self: *BackupMetadata) void {
        for (self.files.items) |file| {
            self.files.allocator.free(file.path);
        }
        self.files.deinit();
    }
};

pub fn saveMetadata(allocator: Allocator, metadata: BackupMetadata, output_dir: []const u8, key: [32]u8) !void {
    // Use existing nonce or generate a new one
    var local_metadata = metadata;
    var metadata_nonce: [12]u8 = undefined;
    
    if (local_metadata.metadata_nonce) |nonce| {
        metadata_nonce = nonce;
    } else {
        metadata_nonce = crypto_utils.generateRandomSalt()[0..12].*;
        local_metadata.metadata_nonce = metadata_nonce;
    }

    const metadata_path = try fs.path.join(allocator, &[_][]const u8{ output_dir, ".cryptbak.meta" });
    defer allocator.free(metadata_path);

    var file = try fs.cwd().createFile(metadata_path, .{});
    defer file.close();

    // Serialize metadata to a buffer
    var buffer = ArrayList(u8).init(allocator);
    defer buffer.deinit();

    // Use existing salt or generate a new one
    var full_salt: [16]u8 = undefined;
    if (local_metadata.key_salt) |salt| {
        full_salt = salt;
    } else {
        full_salt = crypto_utils.generateRandomSalt();
        local_metadata.key_salt = full_salt;
    }
    
    var enc_key: [32]u8 = undefined;
    try crypto_utils.deriveCipherKey(key[0..], full_salt, &enc_key);

    // Write metadata header
    const marker = "CRYPTBAK";
    try file.writeAll(marker);

    // Write file format version, timestamp, and salt as unencrypted header
    var header_buf: [32]u8 = undefined;
    std.mem.writeInt(u32, header_buf[0..4], local_metadata.version, .little);
    std.mem.writeInt(i64, header_buf[4..12], local_metadata.timestamp, .little);
    @memcpy(header_buf[12..28], full_salt[0..]);
    try file.writeAll(&header_buf);

    // Debug output
    debugPrint("SaveMetadata: Timestamp = {d}\n", .{local_metadata.timestamp});
    debugPrint("SaveMetadata: Files count = {d}\n", .{local_metadata.files.items.len});

    // Write nonce
    try file.writeAll(&metadata_nonce);

    debugPrint("SaveMetadata: Nonce bytes = [ ", .{});
    if (config.enable_debug_output) {
        for (metadata_nonce) |b| {
            std.debug.print("{d} ", .{b});
        }
    }
    debugPrint("]\n", .{});

    // Serialize file metadata
    const writer = buffer.writer();

    // Write file count
    var files_count_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &files_count_bytes, @as(u32, @intCast(local_metadata.files.items.len)), .little);
    try writer.writeAll(&files_count_bytes);

    for (local_metadata.files.items) |file_meta| {
        // Write path length
        var path_len_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &path_len_bytes, file_meta.path.len, .little);
        try writer.writeAll(&path_len_bytes);

        // Write path
        try writer.writeAll(file_meta.path);

        // Write last modified time
        var modified_bytes: [16]u8 = undefined;
        std.mem.writeInt(i128, &modified_bytes, file_meta.last_modified, .little);
        try writer.writeAll(&modified_bytes);

        // Write size
        var size_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &size_bytes, file_meta.size, .little);
        try writer.writeAll(&size_bytes);

        // Write file hash
        try writer.writeAll(&file_meta.hash);

        // Write is_directory flag
        try writer.writeByte(if (file_meta.is_directory) 1 else 0);
    }

    // Debug output the serialized data
    debugPrint("SaveMetadata: Serialized data size = {d} bytes\n", .{buffer.items.len});
    debugPrint("SaveMetadata: First bytes of unencrypted data = [ ", .{});
    if (config.enable_debug_output) {
        const max_print = @min(32, buffer.items.len);
        for (buffer.items[0..max_print]) |b| {
            std.debug.print("{d} ", .{b});
        }
    }
    debugPrint("]\n", .{});

    // Encrypt and write the metadata
    const encrypted_buffer = try allocator.alloc(u8, buffer.items.len);
    defer allocator.free(encrypted_buffer);

    // Use a fixed counter value
    const counter: u32 = 0;
    debugPrint("SaveMetadata: Encrypting with counter = {d}\n", .{counter});

    crypto_utils.encrypt(encrypted_buffer, buffer.items, counter, enc_key, metadata_nonce);

    try file.writeAll(encrypted_buffer);
}

pub fn loadMetadata(allocator: Allocator, output_dir: []const u8, key: [32]u8) !BackupMetadata {
    const metadata_path = try fs.path.join(allocator, &[_][]const u8{ output_dir, ".cryptbak.meta" });
    defer allocator.free(metadata_path);

    var file = fs.cwd().openFile(metadata_path, .{}) catch |err| {
        if (err == error.FileNotFound) {
            return BackupMetadata.init(allocator);
        }
        return err;
    };
    defer file.close();

    // Check file marker
    const marker = "CRYPTBAK";
    var marker_buf: [marker.len]u8 = undefined;
    const marker_read = try file.read(&marker_buf);
    if (marker_read != marker_buf.len or !std.mem.eql(u8, &marker_buf, marker)) {
        debugPrint("Metadata: Invalid file marker\n", .{});
        return error.InvalidMetadataFile;
    }
    debugPrint("Metadata: Valid header marker found\n", .{});

    // Read unencrypted metadata header
    var header_buf: [32]u8 = undefined;
    const header_read = try file.read(&header_buf);
    if (header_read != header_buf.len) {
        return error.InvalidMetadataFile;
    }

    // Parse metadata basic information
    const version = std.mem.readInt(u32, header_buf[0..4], .little);
    const timestamp = std.mem.readInt(i64, header_buf[4..12], .little);
    var full_salt: [16]u8 = undefined;
    @memcpy(full_salt[0..], header_buf[12..28]);

    debugPrint("Metadata: Version = {d}\n", .{version});
    debugPrint("Metadata: Timestamp = {d}\n", .{timestamp});

    var metadata = BackupMetadata{
        .version = version,
        .timestamp = timestamp,
        .files = ArrayList(FileMetadata).init(allocator),
        .key_salt = full_salt,
    };

    // Read nonce
    var metadata_nonce: [12]u8 = undefined;
    const nonce_read = try file.read(&metadata_nonce);
    if (nonce_read != metadata_nonce.len) {
        return error.InvalidMetadataFile;
    }

    metadata.metadata_nonce = metadata_nonce;

    debugPrint("LoadMetadata: Nonce bytes = [ ", .{});
    if (config.enable_debug_output) {
        for (metadata_nonce) |b| {
            std.debug.print("{d} ", .{b});
        }
    }
    debugPrint("]\n", .{});

    // Derive a new key for decryption using the salt
    var dec_key: [32]u8 = undefined;
    try crypto_utils.deriveCipherKey(key[0..], full_salt, &dec_key);

    // Read the rest of the file
    const stat = try file.stat();
    // Calculate the size of the encrypted data section = total file size - header size
    const header_size = marker.len + header_buf.len + metadata_nonce.len;
    const encrypted_size = stat.size - header_size;

    debugPrint("LoadMetadata: File size = {d}, Header size = {d}, Encrypted size = {d}\n", .{ stat.size, header_size, encrypted_size });

    if (encrypted_size <= 0) {
        debugPrint("LoadMetadata: No encrypted data section\n", .{});
        return error.InvalidMetadataFile;
    }

    // Read encrypted data
    const encrypted_buffer = try allocator.alloc(u8, encrypted_size);
    defer allocator.free(encrypted_buffer);

    const data_read = try file.read(encrypted_buffer);
    if (data_read != encrypted_size) {
        debugPrint("LoadMetadata: Incomplete data read, expected {d} bytes, got {d}\n", .{ encrypted_size, data_read });
        return error.InvalidMetadataFile;
    }

    // Decrypt data
    const decrypted_buffer = try allocator.alloc(u8, encrypted_size);
    defer allocator.free(decrypted_buffer);

    // Use the same counter value as for encryption
    const counter: u32 = 0;
    debugPrint("LoadMetadata: Decrypting with counter = {d}\n", .{counter});

    crypto_utils.decrypt(decrypted_buffer, encrypted_buffer, counter, dec_key, metadata_nonce);

    // Print the first bytes of the decrypted data for debugging
    debugPrint("LoadMetadata: First bytes of decrypted data = [ ", .{});
    if (config.enable_debug_output) {
        const max_print = @min(32, encrypted_size);
        for (decrypted_buffer[0..max_print]) |b| {
            std.debug.print("{d} ", .{b});
        }
    }
    debugPrint("]\n", .{});

    // Deserialize
    var stream = std.io.fixedBufferStream(decrypted_buffer);
    const reader = stream.reader();

    // Read file count
    var files_count_bytes: [4]u8 = undefined;
    const files_count_read = reader.read(&files_count_bytes) catch |err| {
        debugPrint("Error reading files count: {any}\n", .{err});
        return error.InvalidMetadataFile;
    };

    if (files_count_read != files_count_bytes.len) {
        debugPrint("Incomplete files count read: got {d} of {d} bytes\n", .{ files_count_read, files_count_bytes.len });
        return error.InvalidMetadataFile;
    }

    const files_count = std.mem.readInt(u32, &files_count_bytes, .little);
    debugPrint("Metadata: Files count = {d} (decrypted)\n", .{files_count});

    // Read and add all file metadata
    for (0..files_count) |i| {
        var path_len_bytes: [8]u8 = undefined;
        const path_len_read = reader.read(&path_len_bytes) catch |err| {
            debugPrint("Error reading path_len for file {d}: {any}\n", .{ i, err });
            return error.InvalidMetadataFile;
        };

        if (path_len_read != path_len_bytes.len) {
            debugPrint("Incomplete path_len read for file {d}: got {d} of {d} bytes\n", .{ i, path_len_read, path_len_bytes.len });
            return error.InvalidMetadataFile;
        }

        const path_len = std.mem.readInt(u64, &path_len_bytes, .little);
        if (path_len > 32768) { // Sanity check for path length
            debugPrint("Suspicious path length for file {d}: {d} bytes\n", .{ i, path_len });
            return error.InvalidMetadataFilePath;
        }

        // Additional sanity check - path length should be non-zero
        if (path_len == 0) {
            debugPrint("Invalid zero path length for file {d}\n", .{i});
            return error.InvalidMetadataFilePath;
        }

        const path = try allocator.alloc(u8, path_len);
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

        // Validate that path contains only valid characters
        for (path) |char| {
            if (char == 0) { // Null character in path
                debugPrint("Invalid null character in path for file {d}\n", .{i});
                allocator.free(path);
                return error.InvalidMetadataFilePath;
            }
        }

        // Read last modified time
        var modified_bytes: [16]u8 = undefined;
        const modified_read = reader.read(&modified_bytes) catch |err| {
            debugPrint("Error reading last_modified for file {d}: {any}\n", .{ i, err });
            allocator.free(path);
            return error.InvalidMetadataFile;
        };

        if (modified_read != modified_bytes.len) {
            debugPrint("Incomplete modified_time read for file {d}: got {d} of {d} bytes\n", .{ i, modified_read, modified_bytes.len });
            allocator.free(path);
            return error.InvalidMetadataFile;
        }

        const last_modified = std.mem.readInt(i128, &modified_bytes, .little);

        // Read size
        var size_bytes: [8]u8 = undefined;
        const size_read = reader.read(&size_bytes) catch |err| {
            debugPrint("Error reading size for file {d}: {any}\n", .{ i, err });
            allocator.free(path);
            return error.InvalidMetadataFile;
        };

        if (size_read != size_bytes.len) {
            debugPrint("Incomplete size read for file {d}: got {d} of {d} bytes\n", .{ i, size_read, size_bytes.len });
            allocator.free(path);
            return error.InvalidMetadataFile;
        }

        const size = std.mem.readInt(u64, &size_bytes, .little);

        // Sanity check for file size
        if (size > 1024 * 1024 * 1024 * 100) { // 100 GB max file size
            debugPrint("Suspicious file size for file {d}: {d} bytes\n", .{ i, size });
            allocator.free(path);
            return error.InvalidMetadataFileSize;
        }

        var hash: [32]u8 = undefined;
        const hash_read = reader.read(&hash) catch |err| {
            debugPrint("Error reading hash for file {d}: {any}\n", .{ i, err });
            allocator.free(path);
            return error.InvalidMetadataFile;
        };

        if (hash_read != hash.len) {
            debugPrint("Incomplete hash read for file {d}: got {d} of {d} bytes\n", .{ i, hash_read, hash.len });
            allocator.free(path);
            return error.InvalidMetadataFile;
        }

        // Read is_directory flag
        const is_directory_byte = reader.readByte() catch |err| {
            debugPrint("Error reading is_directory flag for file {d}: {any}\n", .{ i, err });
            allocator.free(path);
            return error.InvalidMetadataFile;
        };

        const is_directory = is_directory_byte == 1;

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

pub fn readMetadataSalt(allocator: Allocator, output_dir: []const u8) !?[16]u8 {
    const metadata_path = try fs.path.join(allocator, &[_][]const u8{ output_dir, ".cryptbak.meta" });
    defer allocator.free(metadata_path);

    var file = fs.cwd().openFile(metadata_path, .{}) catch |err| {
        if (err == error.FileNotFound) {
            return null; // File doesn't exist, return null
        }
        return err;
    };
    defer file.close();

    // Read file marker
    const marker = "CRYPTBAK";
    var marker_buf: [marker.len]u8 = undefined;
    const marker_read = try file.read(&marker_buf);
    if (marker_read != marker_buf.len or !std.mem.eql(u8, &marker_buf, marker)) {
        debugPrint("Invalid file marker\n", .{});
        return error.InvalidMetadataFile;
    }

    // Read unencrypted metadata header
    var header_buf: [32]u8 = undefined;
    const header_read = try file.read(&header_buf);
    if (header_read != header_buf.len) {
        return error.InvalidMetadataFile;
    }

    // Extract salt from header
    var salt: [16]u8 = undefined;
    @memcpy(salt[0..], header_buf[12..28]);
    
    return salt;
}

pub fn findOriginalPathByHash(metadata: BackupMetadata, allocator: Allocator, hash_value: []const u8) !?[]const u8 {
    for (metadata.files.items) |file| {
        if (file.is_directory) continue;

        const content_hash = try crypto_utils.getContentHashedPath(allocator, file.hash);
        defer allocator.free(content_hash);

        if (std.mem.eql(u8, content_hash, hash_value)) {
            return try allocator.dupe(u8, file.path);
        }
    }

    return null;
}

// Unit tests for metadata functionality
test "metadata serialization and deserialization" {
    const testing = std.testing;
    var allocator = testing.allocator;

    // Create a temporary directory for testing
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Get the path to the temporary directory
    const tmp_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    // Create test metadata
    var metadata = BackupMetadata.init(allocator);
    defer metadata.deinit();

    // Add a few test files
    const test_path1 = try allocator.dupe(u8, "test_file1.txt");
    try metadata.files.append(FileMetadata{
        .path = test_path1,
        .last_modified = 123456789,
        .size = 1024,
        .hash = [_]u8{1} ** 32,
        .is_directory = false,
    });

    const test_path2 = try allocator.dupe(u8, "test_directory");
    try metadata.files.append(FileMetadata{
        .path = test_path2,
        .last_modified = 987654321,
        .size = 0,
        .hash = [_]u8{0} ** 32,
        .is_directory = true,
    });

    // Set a test password
    const test_password = "test_password";
    var key: [32]u8 = undefined;
    var initial_salt: [16]u8 = undefined;
    @memset(&initial_salt, 0);
    try crypto_utils.deriveCipherKey(test_password, initial_salt, &key);

    // Save metadata to the temp directory
    try saveMetadata(allocator, metadata, tmp_path, key);

    // Load back the metadata
    var loaded_metadata = try loadMetadata(allocator, tmp_path, key);
    defer loaded_metadata.deinit();

    // Verify the loaded metadata
    try testing.expectEqual(metadata.version, loaded_metadata.version);
    try testing.expectEqual(metadata.timestamp, loaded_metadata.timestamp);
    try testing.expectEqual(metadata.files.items.len, loaded_metadata.files.items.len);

    // Check if files match
    for (metadata.files.items, 0..) |file, i| {
        const loaded_file = loaded_metadata.files.items[i];
        try testing.expectEqualStrings(file.path, loaded_file.path);
        try testing.expectEqual(file.last_modified, loaded_file.last_modified);
        try testing.expectEqual(file.size, loaded_file.size);
        try testing.expectEqualSlices(u8, &file.hash, &loaded_file.hash);
        try testing.expectEqual(file.is_directory, loaded_file.is_directory);
    }
}

test "metadata with empty file list" {
    const testing = std.testing;
    var allocator = testing.allocator;

    // Create a temporary directory for testing
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Get the path to the temporary directory
    const tmp_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    // Create empty metadata
    var metadata = BackupMetadata.init(allocator);
    defer metadata.deinit();

    // Set a test password
    const test_password = "test_password";
    var key: [32]u8 = undefined;
    var initial_salt: [16]u8 = undefined;
    @memset(&initial_salt, 0);
    try crypto_utils.deriveCipherKey(test_password, initial_salt, &key);

    // Save metadata to the temp directory
    try saveMetadata(allocator, metadata, tmp_path, key);

    // Load back the metadata
    var loaded_metadata = try loadMetadata(allocator, tmp_path, key);
    defer loaded_metadata.deinit();

    // Verify the loaded metadata
    try testing.expectEqual(metadata.version, loaded_metadata.version);
    try testing.expectEqual(metadata.timestamp, loaded_metadata.timestamp);
    try testing.expectEqual(@as(usize, 0), loaded_metadata.files.items.len);
}

test "metadata with special characters in file paths" {
    const testing = std.testing;
    var allocator = testing.allocator;

    // Create a temporary directory for testing
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Get the path to the temporary directory
    const tmp_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    // Create test metadata
    var metadata = BackupMetadata.init(allocator);
    defer metadata.deinit();

    // Add a file with special characters in the path
    const special_path = try allocator.dupe(u8, "路径/with spaces and 特殊字符.txt");
    try metadata.files.append(FileMetadata{
        .path = special_path,
        .last_modified = 123456789,
        .size = 1024,
        .hash = [_]u8{1} ** 32,
        .is_directory = false,
    });

    // Set a test password
    const test_password = "test_password";
    var key: [32]u8 = undefined;
    var initial_salt: [16]u8 = undefined;
    @memset(&initial_salt, 0);
    try crypto_utils.deriveCipherKey(test_password, initial_salt, &key);

    // Save metadata to the temp directory
    try saveMetadata(allocator, metadata, tmp_path, key);

    // Load back the metadata
    var loaded_metadata = try loadMetadata(allocator, tmp_path, key);
    defer loaded_metadata.deinit();

    // Verify the special path was preserved
    try testing.expectEqualStrings(special_path, loaded_metadata.files.items[0].path);
}
