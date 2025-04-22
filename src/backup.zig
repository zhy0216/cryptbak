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

// 原始的performBackup函数，保留用于向后兼容
pub fn performBackupLegacy(allocator: Allocator, conf: Config, key: [32]u8, existing_metadata: BackupMetadata) !void {
    debugPrint("Performing backup of {s} to {s}\n", .{ conf.source_dir, conf.output_dir });

    // Scan source directory
    var current_files = ArrayList(FileMetadata).init(allocator);
    defer {
        // Free the path strings as they will be duplicated before adding to new_metadata
        for (current_files.items) |file| {
            allocator.free(file.path);
        }
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

            // Add to metadata with a freshly allocated path
            var file_copy = file;
            file_copy.path = try allocator.dupe(u8, file.path);
            try new_metadata.files.append(file_copy);
            continue;
        }

        // Check if this file needs to be updated
        const needs_update = blk: {
            const existing_file_opt = existing_files_map.get(file.path);
            if (existing_file_opt == null) {
                debugPrint("New file: {s}\n", .{file.path});
                break :blk true;
            }

            const existing_file = existing_file_opt.?;
            if (!std.mem.eql(u8, &existing_file.hash, &file.hash) or existing_file.size != file.size) {
                debugPrint("Changed file: {s}\n", .{file.path});
                break :blk true;
            }

            break :blk false;
        };

        if (needs_update) {
            var nonce: [12]u8 = undefined;
            std.crypto.random.bytes(&nonce);

            // Get the content-based hash path
            const content_hashed_name = try crypto_utils.getContentHashedPath(allocator, file.hash);
            defer allocator.free(content_hashed_name);

            const dest_path = try fs.path.join(allocator, &[_][]const u8{ content_dir, content_hashed_name });
            defer allocator.free(dest_path);

            try crypto_utils.encryptFile(source_path, dest_path, key, nonce);
        }

        // Add to new metadata with a freshly allocated path
        var file_copy = file;
        file_copy.path = try allocator.dupe(u8, file.path);
        try new_metadata.files.append(file_copy);
    }

    // Identify files to remove (in backup but not in source)
    var files_to_remove = ArrayList([]const u8).init(allocator);
    defer {
        for (files_to_remove.items) |path| {
            allocator.free(path);
        }
        files_to_remove.deinit();
    }

    // Create a map of current files for fast lookups
    var current_files_map = StringHashMap(void).init(allocator);
    defer {
        var it = current_files_map.keyIterator();
        while (it.next()) |_| {
            // We don't own these strings, they're borrowed from current_files
        }
        current_files_map.deinit();
    }

    for (current_files.items) |file| {
        try current_files_map.put(file.path, {});
    }

    // Check each file in existing metadata
    for (existing_metadata.files.items) |file| {
        // If it's in existing metadata but not in current files, it's been removed
        if (!current_files_map.contains(file.path)) {
            const path_copy = try allocator.dupe(u8, file.path);
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

        if (content_hash_map.get(content_hash)) |count| {
            // Increment reference count
            try content_hash_map.put(content_hash, count + 1);
            // Free the duplicate hash string
            allocator.free(content_hash);
        } else {
            // First reference to this hash - we transfer ownership of content_hash to the map
            try content_hash_map.put(content_hash, 1);
        }
    }

    // Process files to remove
    for (files_to_remove.items) |file| {
        debugPrint("Checking if we can remove deleted file: {s}\n", .{file});

        // Get the file's metadata from the existing metadata
        for (existing_metadata.files.items) |existing_file| {
            if (std.mem.eql(u8, existing_file.path, file)) {
                // Only handle regular files, not directories
                if (!existing_file.is_directory) {
                    // Get content hash path
                    const content_hash = try crypto_utils.getContentHashedPath(allocator, existing_file.hash);
                    defer allocator.free(content_hash);

                    // Check if this content is referenced by other files
                    if (content_hash_map.get(content_hash)) |count| {
                        debugPrint("File {s} content is still in use by {d} other files\n", .{ file, count });
                    } else {
                        // Content hash not used, remove the file
                        const content_path = try fs.path.join(allocator, &[_][]const u8{ conf.output_dir, "content", content_hash });
                        defer allocator.free(content_path);

                        fs.cwd().deleteFile(content_path) catch |err| {
                            debugPrint("Warning: Failed to delete content file {s}: {any}\n", .{ content_path, err });
                        };
                    }
                }
            }
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

pub fn processBackup(allocator: Allocator, conf: Config, key: [32]u8, existing_metadata: BackupMetadata) !void {
    return performBackup(allocator, conf, key, existing_metadata);
}

pub fn doPartialBackup(allocator: Allocator, conf: Config, events: []const fs_watcher.WatchEvent) !void {
    debugPrint("Performing backup of changed files...\n", .{});
    debugPrint("Number of change events to process: {d}\n", .{events.len});

    // Log event details for debugging
    for (events) |event| {
        debugPrint("Event detected - Path: {s}, Kind: {any}\n", .{ event.path, event.kind });
    }

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
            // If no metadata exists, do a full backup instead
            debugPrint("No existing metadata found, performing full backup instead\n", .{});
            return doEncrypt(allocator, conf);
        }
        return err;
    };
    defer existing_metadata.deinit();

    return performBackup(allocator, conf, key, existing_metadata);
}

// Helper function to check if a file's parent directory is in the changed paths set
fn hasParentInSet(changed_paths: *const StringHashMap(void), path: []const u8) bool {
    const parent_path = fs.path.dirname(path) orelse return false;
    if (parent_path.len == 0) return false;

    return changed_paths.contains(parent_path);
}

// Helper function to update a file in the metadata
fn updateMetadataFile(new_metadata: *BackupMetadata, file: FileMetadata) void {
    // Find and update the file in the metadata
    for (new_metadata.files.items, 0..) |*existing, i| {
        if (std.mem.eql(u8, existing.path, file.path)) {
            // Update the existing entry
            new_metadata.files.items[i] = file;
            return;
        }
    }

    // If not found, append it
    new_metadata.files.append(file) catch |err| {
        debugPrint("Warning: Failed to append file to metadata: {any}\n", .{err});
    };
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
        debugPrint("Files deleted or count mismatch. Existing: {d}, Current: {d}\n", .{ files_in_existing, files_in_current });
        return true;
    }

    // No changes detected
    return false;
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

        try crypto_utils.decryptFile(source_path, dest_path, key);
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

    // 1. Load existing metadata (if available) or create empty metadata
    var existing_metadata = metadata.loadMetadata(allocator, conf.output_dir, key) catch |err| {
        if (err == error.FileNotFound) {
            // If no metadata exists, create an empty one
            const new_empty_metadata = BackupMetadata.init(allocator);
            debugPrint("No existing metadata found, starting with empty metadata\n", .{});
            return performBackup(allocator, conf, key, new_empty_metadata);
        }
        return err;
    };
    defer existing_metadata.deinit();

    return performBackup(allocator, conf, key, existing_metadata);
}

// Refactored version of performBackup that clearly separates the backup process into steps
pub fn performBackup(allocator: Allocator, conf: Config, key: [32]u8, existing_metadata: BackupMetadata) !void {
    debugPrint("Performing backup of {s} to {s}\n", .{ conf.source_dir, conf.output_dir });

    // 2. Scan source directory to calculate new metadata
    var current_files = ArrayList(FileMetadata).init(allocator);
    defer {
        // Free the path strings as they will be duplicated before adding to new_metadata
        for (current_files.items) |file| {
            allocator.free(file.path);
        }
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

    // 3. Compare metadata to identify files to backup and files to delete

    // 3.1. Identify files to backup (new or changed files)
    var files_to_backup = ArrayList(FileMetadata).init(allocator);
    defer {
        for (files_to_backup.items) |file| {
            allocator.free(file.path);
        }
        files_to_backup.deinit();
    }

    for (current_files.items) |file| {
        const existing_file_opt = existing_files_map.get(file.path);
        var needs_update = false;

        if (existing_file_opt == null) {
            debugPrint("New file: {s}\n", .{file.path});
            needs_update = true;
        } else {
            const existing_file = existing_file_opt.?;
            if (!std.mem.eql(u8, &existing_file.hash, &file.hash) or existing_file.size != file.size) {
                debugPrint("Changed file: {s}\n", .{file.path});
                needs_update = true;
            }
        }

        if (needs_update and !file.is_directory) {
            var file_copy = file;
            file_copy.path = try allocator.dupe(u8, file.path);
            try files_to_backup.append(file_copy);
        }

        // Add to new metadata with a freshly allocated path
        var file_copy = file;
        file_copy.path = try allocator.dupe(u8, file.path);
        try new_metadata.files.append(file_copy);
    }

    // 3.2. Identify files to remove (in backup but not in source)
    // Instead of tracking files by path, we track by content hash
    var hashes_in_source = StringHashMap(void).init(allocator);
    defer {
        var hash_key_iter = hashes_in_source.keyIterator();
        while (hash_key_iter.next()) |hash_key| {
            allocator.free(hash_key.*);
        }
        hashes_in_source.deinit();
    }

    // First, collect all content hashes in current source
    for (current_files.items) |file| {
        if (file.is_directory) continue;

        const content_hash = try crypto_utils.getContentHashedPath(allocator, file.hash);

        if (hashes_in_source.contains(content_hash)) {
            // Hash already in map, free the duplicate
            allocator.free(content_hash);
        } else {
            // Add new hash to map
            try hashes_in_source.put(content_hash, {});
        }
    }

    // Print all hashes in source for debugging
    debugPrint("\n=== Content hashes in source ===\n", .{});
    var source_hash_iter = hashes_in_source.keyIterator();
    while (source_hash_iter.next()) |hash_key| {
        debugPrint("Source hash: {s}\n", .{hash_key.*});
    }

    // Print all hashes in existing metadata for debugging
    debugPrint("\n=== Content hashes in existing metadata ===\n", .{});
    for (existing_metadata.files.items) |file| {
        if (file.is_directory) continue;

        const content_hash = try crypto_utils.getContentHashedPath(allocator, file.hash);
        debugPrint("Existing metadata hash: {s}\n", .{content_hash});
        allocator.free(content_hash);
    }

    // Now find content hashes in existing metadata that don't exist in source
    var content_to_remove = ArrayList([]const u8).init(allocator);
    defer {
        for (content_to_remove.items) |hash| {
            allocator.free(hash);
        }
        content_to_remove.deinit();
    }

    for (existing_metadata.files.items) |file| {
        if (file.is_directory) continue;

        const content_hash = try crypto_utils.getContentHashedPath(allocator, file.hash);
        debugPrint("\n=== content_hash: {s} ===\n", .{content_hash});

        if (!hashes_in_source.contains(content_hash)) {
            // This hash is no longer used in source, mark for removal
            try content_to_remove.append(content_hash);
        } else {
            // Hash is still in use, free it
            allocator.free(content_hash);
        }
    }

    // 4. Execute backup and cleanup operations

    // 4.1. Ensure the content directory exists
    const content_dir = try fs.path.join(allocator, &[_][]const u8{ conf.output_dir, "content" });
    defer allocator.free(content_dir);
    try fs.cwd().makePath(content_dir);

    // 4.2. Backup files (encrypt new or changed files)
    for (files_to_backup.items) |file| {
        const source_path = try fs.path.join(allocator, &[_][]const u8{ conf.source_dir, file.path });
        defer allocator.free(source_path);

        var nonce: [12]u8 = undefined;
        std.crypto.random.bytes(&nonce);

        // Get the content-based hash path
        const content_hashed_name = try crypto_utils.getContentHashedPath(allocator, file.hash);
        defer allocator.free(content_hashed_name);

        const dest_path = try fs.path.join(allocator, &[_][]const u8{ content_dir, content_hashed_name });
        defer allocator.free(dest_path);

        try crypto_utils.encryptFile(source_path, dest_path, key, nonce);
    }

    // Create a map to track which content hashes are still in use
    var content_hash_map = StringHashMap(u32).init(allocator);
    defer {
        var hash_iter = content_hash_map.keyIterator();
        while (hash_iter.next()) |hash_key| {
            allocator.free(hash_key.*);
        }
        content_hash_map.deinit();
    }

    // Count references to each content hash in the new metadata
    for (new_metadata.files.items) |file| {
        if (file.is_directory) continue;

        const content_hash = try crypto_utils.getContentHashedPath(allocator, file.hash);

        if (content_hash_map.get(content_hash)) |count| {
            try content_hash_map.put(content_hash, count + 1);
            allocator.free(content_hash); // Free duplicate hash since we didn't store it
        } else {
            // First reference to this hash - we transfer ownership of content_hash to the map
            try content_hash_map.put(content_hash, 1);
        }
    }

    // 4.3. Process files to remove (clean up deleted files)
    for (content_to_remove.items) |content_hash| {
        debugPrint("Checking if we can remove deleted file: {s}\n", .{content_hash});
        const content_path = try fs.path.join(allocator, &[_][]const u8{ content_dir, content_hash });
        defer allocator.free(content_path);

        fs.cwd().deleteFile(content_path) catch |err| {
            debugPrint("Warning: Failed to delete content file {s}: {any}\n", .{ content_path, err });
        };
    }

    // 5. Save new metadata
    try metadata.saveMetadata(allocator, new_metadata, conf.output_dir, key);
    debugPrint("Backup completed successfully!\n", .{});
}

pub fn doWatch(allocator: Allocator, conf: Config) !void {
    debugPrint("Starting watch mode on {s}\n", .{conf.source_dir});
    debugPrint("Minimum backup period: {d} seconds\n", .{conf.min_backup_period});

    // Initial backup
    try doEncrypt(allocator, conf);

    // Set up a timer to track when we last performed a backup
    var last_backup_time = std.time.milliTimestamp();
    var changes_detected = false;

    // Initialize file system watcher
    debugPrint("Initializing file system watcher...\n", .{});
    var watcher_result = try fs_watcher.createWatcher(allocator, conf.source_dir);

    // Start watching
    switch (watcher_result) {
        .FSWatcher => |*native_watcher| {
            defer native_watcher.deinit();
            try native_watcher.start();
            debugPrint("Using native file system notifications\n", .{});

            while (true) {
                // Check for file system events
                changes_detected = try native_watcher.checkEvents();

                // If changes detected and minimum backup period has passed
                const current_time = std.time.milliTimestamp();
                const elapsed_ms = current_time - last_backup_time;
                const min_period_ms = conf.min_backup_period * std.time.ms_per_s;

                if (changes_detected and elapsed_ms >= min_period_ms) {
                    debugPrint("Changes detected, performing partial backup...\n", .{});
                    try doPartialBackup(allocator, conf, native_watcher.events.items);
                    last_backup_time = std.time.milliTimestamp();
                    changes_detected = false;
                } else if (changes_detected) {
                    debugPrint("Changes detected, but waiting for minimum backup period ({d} seconds)...\n", .{conf.min_backup_period});

                    // Continue checking until minimum period has passed
                    while (true) {
                        std.time.sleep(std.time.ns_per_s); // 1 second sleep

                        const check_time = std.time.milliTimestamp();
                        const check_elapsed = check_time - last_backup_time;

                        if (check_elapsed >= min_period_ms) {
                            debugPrint("Minimum period reached, performing partial backup...\n", .{});
                            try doPartialBackup(allocator, conf, native_watcher.events.items);
                            last_backup_time = std.time.milliTimestamp();
                            changes_detected = false;
                            break;
                        }
                    }
                }

                // Small sleep to prevent high CPU usage
                std.time.sleep(std.time.ns_per_s / 10); // 100ms sleep
            }
        },
        .PollingFSWatcher => |*polling_watcher| {
            defer polling_watcher.deinit();
            try polling_watcher.start();
            debugPrint("Using polling-based file system monitoring\n", .{});

            while (true) {
                // Check for file system events
                changes_detected = try polling_watcher.checkEvents();

                // If changes detected and minimum backup period has passed
                const current_time = std.time.milliTimestamp();
                const elapsed_ms = current_time - last_backup_time;
                const min_period_ms = conf.min_backup_period * std.time.ms_per_s;

                if (changes_detected and elapsed_ms >= min_period_ms) {
                    debugPrint("Changes detected, performing partial backup...\n", .{});
                    try doPartialBackup(allocator, conf, polling_watcher.events.items);
                    last_backup_time = std.time.milliTimestamp();
                    changes_detected = false;
                } else if (changes_detected) {
                    debugPrint("Changes detected, but waiting for minimum backup period ({d} seconds)...\n", .{conf.min_backup_period});

                    // Continue checking until minimum period has passed
                    while (true) {
                        std.time.sleep(std.time.ns_per_s); // 1 second sleep

                        const check_time = std.time.milliTimestamp();
                        const check_elapsed = check_time - last_backup_time;

                        if (check_elapsed >= min_period_ms) {
                            debugPrint("Minimum period reached, performing partial backup...\n", .{});
                            try doPartialBackup(allocator, conf, polling_watcher.events.items);
                            last_backup_time = std.time.milliTimestamp();
                            changes_detected = false;
                            break;
                        }
                    }
                }

                // Small sleep to prevent high CPU usage
                std.time.sleep(std.time.ns_per_s * 2); // 2 second polling interval
            }
        },
    }
}

const fs_watcher = @import("fs_watcher.zig");

pub fn doIntegrityCheck(allocator: Allocator, conf: Config) !void {
    debugPrint("Checking backup integrity for {s}\n", .{conf.output_dir});

    // Get the key from the password
    var salt: [16]u8 = undefined;
    var key: [32]u8 = undefined;

    // First try to get the salt from the existing metadata
    const metadata_path = try fs.path.join(allocator, &[_][]const u8{ conf.output_dir, ".cryptbak.meta" });
    defer allocator.free(metadata_path);

    // Open the metadata file
    var meta_file = fs.cwd().openFile(metadata_path, .{}) catch |err| {
        debugPrint("Error: Cannot open metadata file: {s}\n", .{@errorName(err)});
        return error.NoMetadataFile;
    };
    defer meta_file.close();

    // Read the header to get the salt
    var marker_buf: [8]u8 = undefined;
    const marker_read = try meta_file.read(&marker_buf);
    if (marker_read != 8 or !std.mem.eql(u8, &marker_buf, "CRYPTBAK")) {
        debugPrint("Error: Invalid metadata file format\n", .{});
        return error.InvalidMetadataFile;
    }

    var header_buf: [32]u8 = undefined;
    const header_read = try meta_file.read(&header_buf);
    if (header_read != 32) {
        debugPrint("Error: Incomplete metadata header\n", .{});
        return error.InvalidMetadataFile;
    }

    // Extract salt from header
    @memcpy(salt[0..], header_buf[12..28]);

    try crypto_utils.deriveCipherKey(conf.password, salt, &key);

    // Try to load existing metadata
    var existing_metadata = metadata.loadMetadata(allocator, conf.output_dir, key) catch |err| {
        debugPrint("Warning: Potential metadata issue detected: {s}\n", .{@errorName(err)});

        // Create and save a new empty metadata as a fallback
        var new_empty_metadata = BackupMetadata.init(allocator);
        defer new_empty_metadata.deinit();

        // Even if metadata is corrupted, check if content directory exists
        const content_dir = try fs.path.join(allocator, &[_][]const u8{ conf.output_dir, "content" });
        defer allocator.free(content_dir);

        // Check if content directory exists
        fs.cwd().access(content_dir, .{}) catch {
            debugPrint("Error: Content directory not found: {s}\n", .{content_dir});
            return error.ContentDirectoryMissing;
        };

        // Save the new empty metadata file
        try metadata.saveMetadata(allocator, new_empty_metadata, conf.output_dir, key);
        std.debug.print("Created new metadata file due to corruption of the original\n", .{});
        std.debug.print("Recommendation: Run a full backup to restore consistency\n", .{});
        return;
    };
    defer existing_metadata.deinit();

    debugPrint("Loaded metadata with {d} files\n", .{existing_metadata.files.items.len});

    // Ensure the content directory exists
    const content_dir = try fs.path.join(allocator, &[_][]const u8{ conf.output_dir, "content" });
    defer allocator.free(content_dir);

    fs.cwd().access(content_dir, .{}) catch {
        debugPrint("Error: Content directory not found: {s}\n", .{content_dir});
        return error.ContentDirectoryMissing;
    };

    // Create a copy of metadata for tracking missing files
    var new_metadata = BackupMetadata.init(allocator);
    defer new_metadata.deinit();

    // Track files that were found to be missing
    var missing_files = ArrayList([]const u8).init(allocator);
    defer {
        for (missing_files.items) |path| {
            allocator.free(path);
        }
        missing_files.deinit();
    }

    // Check each file in the metadata
    for (existing_metadata.files.items) |file| {
        // Skip directories, they don't have content files
        if (file.is_directory) {
            // Add directories directly to new metadata
            var file_copy = file;
            file_copy.path = try allocator.dupe(u8, file.path);
            try new_metadata.files.append(file_copy);
            continue;
        }

        // Get the content hash path
        const content_hash = try crypto_utils.getContentHashedPath(allocator, file.hash);
        defer allocator.free(content_hash);

        // Check if content file exists
        const content_path = try fs.path.join(allocator, &[_][]const u8{ content_dir, content_hash });
        defer allocator.free(content_path);

        var file_exists = true;
        fs.cwd().access(content_path, .{}) catch {
            file_exists = false;
        };

        if (file_exists) {
            // Add to new metadata with a freshly allocated path
            var file_copy = file;
            file_copy.path = try allocator.dupe(u8, file.path);
            try new_metadata.files.append(file_copy);
        } else {
            // File is missing
            const missing_path = try allocator.dupe(u8, file.path);
            try missing_files.append(missing_path);
            debugPrint("Missing file detected: {s} (content hash: {s})\n", .{ file.path, content_hash });
        }
    }

    // Report results
    if (missing_files.items.len > 0) {
        debugPrint("\nIntegrity check results:\n", .{});
        debugPrint("-----------------------\n", .{});
        debugPrint("Found {d} missing files out of {d} total files\n", .{ missing_files.items.len, existing_metadata.files.items.len });

        for (missing_files.items) |path| {
            debugPrint("  - {s}\n", .{path});
        }

        // Save the updated metadata without the missing files
        debugPrint("\nUpdating metadata to remove missing files...\n", .{});
        try metadata.saveMetadata(allocator, new_metadata, conf.output_dir, key);
        debugPrint("Metadata updated successfully. Re-run backup to restore missing files.\n", .{});
    } else {
        debugPrint("\nIntegrity check completed successfully!\n", .{});
        debugPrint("All {d} files in metadata were found in the backup.\n", .{existing_metadata.files.items.len});
    }
}
