const std = @import("std");
const fs = std.fs;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const StringHashMap = std.StringHashMap;

const config = @import("config.zig");
const metadata = @import("metadata.zig");
const crypto_utils = @import("crypto_utils.zig");
const fs_utils = @import("fs_utils.zig");
const debugPrint = config.debugPrint;

const Config = config.Config;
const BackupMetadata = metadata.BackupMetadata;
const FileMetadata = metadata.FileMetadata;

pub fn processBackup(allocator: Allocator, conf: Config, key: [32]u8, existing_metadata: BackupMetadata) !void {
    // Scan source directory
    var current_files = ArrayList(FileMetadata).init(allocator);
    defer {
        // Don't free the path strings as they are transferred to new_metadata
        current_files.deinit();
    }

    try fs_utils.scanDirectory(allocator, conf.source_dir, conf.source_dir, &current_files);

    // Build a map of existing files for fast lookups
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
        const dest_path = try fs.path.join(allocator, &[_][]const u8{ conf.output_dir, file.path });
        defer allocator.free(dest_path);

        const source_path = try fs.path.join(allocator, &[_][]const u8{ conf.source_dir, file.path });
        defer allocator.free(source_path);

        // If it's a directory, just create it
        if (file.is_directory) {
            debugPrint("Creating empty directory: {s}\n", .{file.path});
            try fs.cwd().makePath(dest_path);
            try new_metadata.files.append(file);
            continue;
        }

        const existing = existing_files_map.get(file.path);
        const needs_update = blk: {
            if (existing == null) {
                debugPrint("New file: {s}\n", .{file.path});
                break :blk true;
            }

            const existing_file = existing.?;
            if (!std.mem.eql(u8, &existing_file.hash, &file.hash) or existing_file.size != file.size) {
                debugPrint("Changed file: {s}\n", .{file.path});
                break :blk true;
            }

            break :blk false;
        };

        if (needs_update) {
            var nonce: [12]u8 = undefined;
            std.crypto.random.bytes(&nonce);

            const enc_key = key;

            try crypto_utils.encryptFile(source_path, dest_path, enc_key, nonce);
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

    var existing_iter = existing_files_map.keyIterator();
    while (existing_iter.next()) |existing_key| {
        var found = false;

        for (new_metadata.files.items) |current| {
            if (std.mem.eql(u8, current.path, existing_key.*)) {
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
        const full_path = try fs.path.join(allocator, &[_][]const u8{ conf.output_dir, file });
        defer allocator.free(full_path);

        debugPrint("Removing deleted file: {s}\n", .{file});
        fs.cwd().deleteFile(full_path) catch |err| {
            debugPrint("Warning: Could not delete {s}: {any}\n", .{ full_path, err });
        };
    }

    // Save new metadata
    try metadata.saveMetadata(allocator, new_metadata, conf.output_dir, key);
    debugPrint("Backup completed successfully!\n", .{});
}

pub fn doDecrypt(allocator: Allocator, conf: Config) !void {
    debugPrint("Decrypting {s} to {s}\n", .{ conf.source_dir, conf.output_dir });

    // Ensure output directory exists
    try fs.cwd().makePath(conf.output_dir);

    // Convert password to key (use deriveCipherKey instead of direct copy)
    var key: [32]u8 = undefined;
    var initial_salt: [16]u8 = undefined;
    @memset(&initial_salt, 0); // Use all-zero salt for initialization
    try crypto_utils.deriveCipherKey(conf.password, initial_salt, &key);

    // Load metadata
    var meta = try metadata.loadMetadata(allocator, conf.source_dir, key);
    defer meta.deinit();

    // Process each file in the metadata
    for (meta.files.items) |file| {
        const source_path = try fs.path.join(allocator, &[_][]const u8{ conf.source_dir, file.path });
        defer allocator.free(source_path);

        const dest_path = try fs.path.join(allocator, &[_][]const u8{ conf.output_dir, file.path });
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

        try crypto_utils.decryptFile(source_path, dest_path, dec_key);
    }

    debugPrint("Decryption completed successfully!\n", .{});
}

pub fn doEncrypt(allocator: Allocator, conf: Config) !void {
    debugPrint("Encrypting {s} to {s}\n", .{ conf.source_dir, conf.output_dir });

    // Ensure output directory exists
    try fs.cwd().makePath(conf.output_dir);

    // Use all-zero initial salt for key derivation, matching doDecrypt
    var initial_salt: [16]u8 = undefined;
    @memset(&initial_salt, 0); // Use all-zero salt for initialization
    var key: [32]u8 = undefined;
    try crypto_utils.deriveCipherKey(conf.password, initial_salt, &key);

    // Try to load existing metadata
    var empty_metadata = BackupMetadata.init(allocator);
    defer empty_metadata.deinit();

    var existing_metadata = metadata.loadMetadata(allocator, conf.output_dir, key) catch |err| {
        if (err == error.FileNotFound) {
            // If no metadata exists, return an empty one
            return processBackup(allocator, conf, key, empty_metadata);
        }
        return err;
    };
    defer existing_metadata.deinit();

    return processBackup(allocator, conf, key, existing_metadata);
}
