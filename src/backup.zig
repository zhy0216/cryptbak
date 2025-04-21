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

    // Ensure the content directory exists
    const content_dir = try fs.path.join(allocator, &[_][]const u8{ conf.output_dir, "content" });
    defer allocator.free(content_dir);
    try fs.cwd().makePath(content_dir);

    // Process each file: only encrypt if changed or new
    for (current_files.items) |file| {
        const source_path = try fs.path.join(allocator, &[_][]const u8{ conf.source_dir, file.path });
        defer allocator.free(source_path);

        // If it's a directory, don't create it in the backup structure, just record in metadata
        if (file.is_directory) {
            debugPrint("Recording directory in metadata (not creating in backup): {s}\n", .{file.path});
            try new_metadata.files.append(file);
            continue;
        }

        // For files, create a content-based hashed filename and store in content directory
        const content_hashed_name = try crypto_utils.getContentHashedPath(allocator, file.hash);
        defer allocator.free(content_hashed_name);

        const dest_path = try fs.path.join(allocator, &[_][]const u8{ content_dir, content_hashed_name });
        defer allocator.free(dest_path);

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

    // Create a map to track which content hashes are still in use
    var content_hash_map = StringHashMap(u32).init(allocator);
    defer content_hash_map.deinit();

    // Count references to each content hash in the new metadata
    for (new_metadata.files.items) |file| {
        if (file.is_directory) continue;

        const content_hash = try crypto_utils.getContentHashedPath(allocator, file.hash);

        const entry = content_hash_map.getEntry(content_hash);
        if (entry) |e| {
            // Increment reference count
            const new_count = e.value_ptr.* + 1;
            allocator.free(content_hash); // Free this copy since we already have the key
            try content_hash_map.put(e.key_ptr.*, new_count);
        } else {
            // First reference to this hash - we transfer ownership of content_hash to the map
            try content_hash_map.put(content_hash, 1);
        }
    }

    // Process files to remove
    for (files_to_remove.items) |file| {
        debugPrint("Checking if we can remove deleted file: {s}\n", .{file});

        // Get the file's metadata from the existing metadata
        const existing_file = existing_files_map.get(file) orelse continue;

        // Get content hash for this file
        const content_hash = try crypto_utils.getContentHashedPath(allocator, existing_file.hash);
        defer allocator.free(content_hash);

        // Check if any other files are using this content hash
        // Note: We need to check if this hash exists in the map
        const ref_count = content_hash_map.get(content_hash) orelse 0;

        if (ref_count == 0) {
            // No references to this content hash, safe to delete
            const full_path = try fs.path.join(allocator, &[_][]const u8{ content_dir, content_hash });
            defer allocator.free(full_path);

            debugPrint("Removing deleted file (no other references): {s}\n", .{file});
            fs.cwd().deleteFile(full_path) catch |err| {
                debugPrint("Warning: Could not delete {s}: {any}\n", .{ full_path, err });
            };
        } else {
            debugPrint("Keeping backup file for deleted {s} as it's referenced by {d} other file(s)\n", .{ file, ref_count });
        }
    }

    // Free the hash map keys - we own these strings
    var hash_iter = content_hash_map.keyIterator();
    while (hash_iter.next()) |hash_key| {
        allocator.free(hash_key.*);
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

    // Get content directory path
    const content_dir = try fs.path.join(allocator, &[_][]const u8{ conf.source_dir, "content" });
    defer allocator.free(content_dir);

    // First, create all directory structures from metadata
    for (meta.files.items) |file| {
        if (file.is_directory) {
            const dest_path = try fs.path.join(allocator, &[_][]const u8{ conf.output_dir, file.path });
            defer allocator.free(dest_path);

            debugPrint("Creating directory from metadata: {s}\n", .{file.path});
            try fs.cwd().makePath(dest_path);
        }
    }

    // Then process each file in the metadata
    for (meta.files.items) |file| {
        // Skip directories as we've already created them
        if (file.is_directory) {
            continue;
        }

        const dest_path = try fs.path.join(allocator, &[_][]const u8{ conf.output_dir, file.path });
        defer allocator.free(dest_path);

        // For files, get the content-based hashed name and decrypt from content directory
        const content_hashed_name = try crypto_utils.getContentHashedPath(allocator, file.hash);
        defer allocator.free(content_hashed_name);

        const source_path = try fs.path.join(allocator, &[_][]const u8{ content_dir, content_hashed_name });
        defer allocator.free(source_path);

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

pub fn doWatch(allocator: Allocator, conf: Config) !void {
    debugPrint("Starting watch mode on {s}\n", .{conf.source_dir});
    debugPrint("Minimum backup period: {d} seconds\n", .{conf.min_backup_period});
    
    // Initial backup
    try doEncrypt(allocator, conf);
    
    // Set up a timer to track when we last performed a backup
    var last_backup_time = std.time.milliTimestamp();
    var changes_detected = false;
    
    while (true) {
        // Store current metadata for comparison
        var initial_salt: [16]u8 = undefined;
        @memset(&initial_salt, 0); // Use all-zero salt for initialization
        var key: [32]u8 = undefined;
        try crypto_utils.deriveCipherKey(conf.password, initial_salt, &key);
        
        var existing_metadata = metadata.loadMetadata(allocator, conf.output_dir, key) catch |err| {
            if (err == error.FileNotFound) {
                var empty_metadata = BackupMetadata.init(allocator);
                defer empty_metadata.deinit();
                continue;
            }
            return err;
        };
        defer existing_metadata.deinit();
        
        // Wait a short time before checking for changes (to reduce CPU usage)
        std.time.sleep(std.time.ns_per_s * 2); // 2 second polling interval
        
        // Scan current directory state
        var current_files = ArrayList(FileMetadata).init(allocator);
        defer {
            for (current_files.items) |file| {
                if (!file.is_directory) allocator.free(file.path);
            }
            current_files.deinit();
        }
        
        try fs_utils.scanDirectory(allocator, conf.source_dir, conf.source_dir, &current_files);
        
        // Compare with previous state to detect changes
        changes_detected = try detectChanges(allocator, &existing_metadata, &current_files);
        
        // If changes detected and minimum backup period has passed
        const current_time = std.time.milliTimestamp();
        const elapsed_ms = current_time - last_backup_time;
        const min_period_ms = conf.min_backup_period * std.time.ms_per_s;
        
        if (changes_detected and elapsed_ms >= min_period_ms) {
            debugPrint("Changes detected, performing backup...\n", .{});
            try doEncrypt(allocator, conf);
            last_backup_time = std.time.milliTimestamp();
            changes_detected = false;
        } else if (changes_detected) {
            debugPrint("Changes detected, but waiting for minimum backup period ({d} seconds)...\n", .{conf.min_backup_period});
        }
    }
}

fn detectChanges(allocator: Allocator, existing_metadata: *BackupMetadata, current_files: *ArrayList(FileMetadata)) !bool {
    // Build a map of existing files for fast lookups
    var existing_files_map = StringHashMap(FileMetadata).init(allocator);
    defer existing_files_map.deinit();
    
    for (existing_metadata.files.items) |file| {
        try existing_files_map.put(file.path, file);
    }
    
    // Check for new or modified files
    for (current_files.items) |file| {
        const existing = existing_files_map.get(file.path);
        
        if (existing == null) {
            // New file
            debugPrint("New file detected: {s}\n", .{file.path});
            return true;
        }
        
        const existing_file = existing.?;
        if (!std.mem.eql(u8, &existing_file.hash, &file.hash) or existing_file.size != file.size) {
            // File has been modified
            debugPrint("Modified file detected: {s}\n", .{file.path});
            return true;
        }
    }
    
    // Check for deleted files
    const files_in_existing = existing_files_map.count();
    const files_in_current = current_files.items.len;
    
    if (files_in_existing != files_in_current) {
        debugPrint("Files deleted or count mismatch. Existing: {d}, Current: {d}\n", .{files_in_existing, files_in_current});
        return true;
    }
    
    // No changes detected
    return false;
}
