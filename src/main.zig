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

    // 写入salt值，以便解密时使用
    var salt: [16]u8 = undefined;
    std.crypto.random.bytes(&salt);
    try file.writeAll(&salt);
    
    std.debug.print("SaveMetadata: Salt bytes = [ ", .{});
    for (salt) |b| {
        std.debug.print("{d} ", .{b});
    }
    std.debug.print("]\n", .{});

    // 添加元数据标记，用于验证
    const METADATA_MARKER = [_]u8{ 'C', 'R', 'Y', 'P', 'T', 'B', 'A', 'K' };
    try file.writeAll(&METADATA_MARKER);
    
    // 写入不加密的版本、时间戳和文件数量
    var header_buf: [20]u8 = undefined; // 4(version) + 8(timestamp) + 8(files_count)
    std.mem.writeInt(u32, header_buf[0..4], metadata.version, .little);
    std.mem.writeInt(i64, header_buf[4..12], metadata.timestamp, .little);
    std.mem.writeInt(u64, header_buf[12..20], metadata.files.items.len, .little);
    try file.writeAll(&header_buf);
    
    std.debug.print("SaveMetadata: Version = {d}\n", .{metadata.version});
    std.debug.print("SaveMetadata: Timestamp = {d}\n", .{metadata.timestamp});
    std.debug.print("SaveMetadata: Files count = {d}\n", .{metadata.files.items.len});

    // Write nonce
    try file.writeAll(&nonce);
    
    std.debug.print("SaveMetadata: Nonce bytes = [ ", .{});
    for (nonce) |b| {
        std.debug.print("{d} ", .{b});
    }
    std.debug.print("]\n", .{});

    // 如果没有文件，就不需要加密和写入文件详情
    if (metadata.files.items.len == 0) {
        return;
    }

    // 使用salt派生一个新密钥进行加密
    var enc_key: [32]u8 = undefined;
    try deriveCipherKey(key[0..], salt, &enc_key);

    // Serialize metadata 文件详细信息部分
    var buffer = ArrayList(u8).init(allocator);
    defer buffer.deinit();

    const writer = buffer.writer();
    
    // 文件详细信息部分不再包含版本、时间戳和文件数量
    for (metadata.files.items) |file_meta| {
        try writer.writeInt(u64, file_meta.path.len, .little);
        try writer.writeAll(file_meta.path);
        try writer.writeInt(i128, file_meta.last_modified, .little);
        try writer.writeInt(u64, file_meta.size, .little);
        try writer.writeAll(&file_meta.hash);
    }

    // 打印要加密的第一部分数据用于调试
    std.debug.print("SaveMetadata: First bytes to encrypt = [ ", .{});
    const max_print = @min(32, buffer.items.len);
    for (buffer.items[0..max_print]) |b| {
        std.debug.print("{d} ", .{b});
    }
    std.debug.print("]\n", .{});

    // Encrypt and write the metadata
    const encrypted_buffer = try allocator.alloc(u8, buffer.items.len);
    defer allocator.free(encrypted_buffer);

    // 使用一个固定的计数器值
    const counter: u32 = 0;
    std.debug.print("SaveMetadata: Encrypting with counter = {d}\n", .{counter});
    
    crypto.stream.chacha.ChaCha20IETF.xor(encrypted_buffer, buffer.items, counter,
        enc_key, nonce);

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

    std.debug.print("Metadata: Salt bytes = [ ", .{});
    for (salt) |b| {
        std.debug.print("{d} ", .{b});
    }
    std.debug.print("]\n", .{});

    // 读取元数据标记
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
    std.debug.print("Metadata: Valid header marker found\n", .{});
    
    // 读取未加密的元数据头部
    var header_buf: [20]u8 = undefined;
    const header_read = try file.read(&header_buf);
    if (header_read != header_buf.len) {
        return error.InvalidMetadataFile;
    }
    
    // 解析元数据基本信息
    const version = std.mem.readInt(u32, header_buf[0..4], .little);
    const timestamp = std.mem.readInt(i64, header_buf[4..12], .little);
    const files_count = std.mem.readInt(u64, header_buf[12..20], .little);
    
    std.debug.print("Metadata: Version = {d}\n", .{version});
    std.debug.print("Metadata: Timestamp = {d}\n", .{timestamp});
    std.debug.print("Metadata: Files count = {d}\n", .{files_count});
    
    // 检查文件数量是否合理
    if (files_count > 100000) {
        std.debug.print("Metadata: Files count too large: {d}\n", .{files_count});
        return error.InvalidMetadataFile;
    }
    
    // 创建元数据结构
    var metadata = BackupMetadata.init(allocator);
    metadata.version = version;
    metadata.timestamp = timestamp;
    
    // 如果没有文件，直接返回
    if (files_count == 0) {
        return metadata;
    }

    // Read nonce
    var nonce: [12]u8 = undefined;
    const nonce_read = try file.read(&nonce);
    if (nonce_read != nonce.len) {
        return error.InvalidMetadataFile;
    }

    std.debug.print("Metadata: Nonce bytes = [ ", .{});
    for (nonce) |b| {
        std.debug.print("{d} ", .{b});
    }
    std.debug.print("]\n", .{});

    // 使用salt派生一个新密钥进行解密
    var dec_key: [32]u8 = undefined;
    try deriveCipherKey(key[0..], salt, &dec_key);

    // Read the rest of the file
    const stat = try file.stat();
    // 计算加密数据部分的大小 = 文件总大小 - 头部大小
    // 头部包括: salt(16) + marker(8) + header_buf(20) + nonce(12)
    const header_size = salt.len + marker.len + header_buf.len + nonce.len;
    const encrypted_size = stat.size - header_size;
    
    std.debug.print("Metadata: File total size = {d}, header size = {d}, encrypted size = {d}\n", 
        .{stat.size, header_size, encrypted_size});
    
    if (encrypted_size <= 0) {
        std.debug.print("Metadata: No encrypted data\n", .{});
        return metadata;
    }

    // 预先为 ArrayList 分配足够的容量
    try metadata.files.ensureTotalCapacity(files_count);

    const encrypted_buffer = try allocator.alloc(u8, encrypted_size);
    defer allocator.free(encrypted_buffer);

    const bytes_read = try file.read(encrypted_buffer);
    if (bytes_read != encrypted_size) {
        std.debug.print("Metadata: Failed to read encrypted data. Expected {d} bytes, got {d}\n", 
            .{encrypted_size, bytes_read});
        return error.InvalidMetadataFile;
    }

    // Decrypt the data
    const decrypted_buffer = try allocator.alloc(u8, encrypted_size);
    defer allocator.free(decrypted_buffer);

    // 使用与加密相同的计数器值
    const counter: u32 = 0;
    std.debug.print("LoadMetadata: Decrypting with counter = {d}\n", .{counter});
    
    crypto.stream.chacha.ChaCha20IETF.xor(decrypted_buffer, encrypted_buffer, counter,
        dec_key, nonce);
        
    // 打印解密后的前32个字节用于调试
    std.debug.print("LoadMetadata: First bytes of decrypted data = [ ", .{});
    const max_print = @min(32, decrypted_buffer.len);
    for (decrypted_buffer[0..max_print]) |b| {
        std.debug.print("{d} ", .{b});
    }
    std.debug.print("]\n", .{});

    // Deserialize
    var stream = std.io.fixedBufferStream(decrypted_buffer);
    const reader = stream.reader();

    // 读取并添加所有文件元数据
    for (0..files_count) |i| {
        var path_len_bytes: [8]u8 = undefined;
        const path_len_read = reader.read(&path_len_bytes) catch |err| {
            std.debug.print("Error reading path_len for file {d}: {any}\n", .{i, err});
            return error.InvalidMetadataFile;
        };

        if (path_len_read != path_len_bytes.len) {
            std.debug.print("Incomplete path_len read for file {d}: got {d} bytes\n", .{i, path_len_read});
            return error.InvalidMetadataFile;
        }

        const path_len = std.mem.readInt(u64, &path_len_bytes, .little);
        std.debug.print("LoadMetadata: File {d} path length = {d}\n", .{i, path_len});

        // 添加最大路径长度限制，防止内存分配问题
        const MAX_PATH_LEN: u64 = 1024;
        if (path_len == 0 or path_len > MAX_PATH_LEN) {
            std.debug.print("Invalid path length {d} for file {d}\n", .{path_len, i});
            return error.InvalidMetadataFile;
        }

        const path = allocator.alloc(u8, path_len) catch |err| {
            std.debug.print("Failed to allocate memory for path: {any}\n", .{err});
            return error.InvalidMetadataFile;
        };
        errdefer allocator.free(path);
        
        const path_read = reader.read(path) catch |err| {
            std.debug.print("Error reading path data: {any}\n", .{err});
            allocator.free(path);
            return error.InvalidMetadataFile;
        };

        if (path_read != path_len) {
            std.debug.print("Incomplete path read for file {d}: got {d} of {d} bytes\n", 
                .{i, path_read, path_len});
            allocator.free(path);
            return error.InvalidMetadataFile;
        }

        var last_modified_bytes: [16]u8 = undefined;
        const last_mod_read = reader.read(&last_modified_bytes) catch |err| {
            std.debug.print("Error reading last_modified: {any}\n", .{err});
            allocator.free(path);
            return error.InvalidMetadataFile;
        };

        if (last_mod_read != last_modified_bytes.len) {
            std.debug.print("Incomplete last_modified read for file {d}\n", .{i});
            allocator.free(path);
            return error.InvalidMetadataFile;
        }

        const last_modified = std.mem.readInt(i128, &last_modified_bytes, .little);

        var size_bytes: [8]u8 = undefined;
        const size_read = reader.read(&size_bytes) catch |err| {
            std.debug.print("Error reading size: {any}\n", .{err});
            allocator.free(path);
            return error.InvalidMetadataFile;
        };

        if (size_read != size_bytes.len) {
            std.debug.print("Incomplete size read for file {d}\n", .{i});
            allocator.free(path);
            return error.InvalidMetadataFile;
        }

        const size = std.mem.readInt(u64, &size_bytes, .little);

        var hash: [32]u8 = undefined;
        const hash_read = reader.read(&hash) catch |err| {
            std.debug.print("Error reading hash: {any}\n", .{err});
            allocator.free(path);
            return error.InvalidMetadataFile;
        };

        if (hash_read != hash.len) {
            std.debug.print("Incomplete hash read for file {d}\n", .{i});
            allocator.free(path);
            return error.InvalidMetadataFile;
        }

        metadata.files.append(FileMetadata{
            .path = path,
            .last_modified = last_modified,
            .size = size,
            .hash = hash,
        }) catch |err| {
            std.debug.print("Failed to append file metadata: {any}\n", .{err});
            allocator.free(path);
            return error.InvalidMetadataFile;
        };
    }
    
    // 检查读取的文件数量是否与预期相符
    if (metadata.files.items.len != files_count) {
        std.debug.print("File count mismatch: expected {d}, got {d}\n", .{files_count, metadata.files.items.len});
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

    // 使用全零的初始盐值用于派生密钥，与doDecrypt函数保持一致
    var initial_salt: [16]u8 = undefined;
    @memset(&initial_salt, 0); // 使用全零盐值用于初始化
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

fn processBackup(allocator: Allocator, config: Config, key: [32]u8, existing_metadata: BackupMetadata) !void {
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

    // 密码转换为密钥 (使用deriveCipherKey而不是直接复制)
    var key: [32]u8 = undefined;
    var initial_salt: [16]u8 = undefined;
    @memset(&initial_salt, 0); // 使用全零盐值用于初始化
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
