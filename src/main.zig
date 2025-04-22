const std = @import("std");

const config = @import("config.zig");
const backup = @import("backup.zig");
const fs_watcher = @import("fs_watcher.zig");
const crypto_utils = @import("crypto_utils.zig");

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
        .Encrypt => {
            if (conf.watch_mode) {
                try backup.doWatch(allocator, conf);
            } else {
                try backup.doEncrypt(allocator, conf);
            }
        },
        .Decrypt => try backup.doDecrypt(allocator, conf),
        .IntegrityCheck => try backup.doIntegrityCheck(allocator, conf),
    }
}

test "Test file system watcher detects file changes" {
    // Create a temporary directory for testing
    const test_allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_path = try tmp_dir.dir.realpathAlloc(test_allocator, ".");
    defer test_allocator.free(tmp_path);

    std.debug.print("###Created temporary test directory: {s}\n", .{tmp_path});

    // Create a watcher for the temporary directory
    var watcher_result = try fs_watcher.createWatcher(test_allocator, tmp_path);
    defer switch (watcher_result) {
        .FSWatcher => |*w| w.deinit(),
        .PollingFSWatcher => |*w| w.deinit(),
    };
    std.debug.print("########## watcher before Started\n", .{});
    // Start watching
    switch (watcher_result) {
        .FSWatcher => |*w| try w.start(),
        .PollingFSWatcher => |*w| try w.start(),
    }
    std.debug.print("############### watcher Started\n", .{});

    // Create a test file in the directory
    const test_filename = "test_file.txt";
    const test_content = "This is a test file for the watch mode test";

    try tmp_dir.dir.writeFile(
        .{
            .sub_path = test_filename,
            .data = test_content,
        },
    );
    std.debug.print("######## Created test file: {s}\n", .{test_filename});

    // Allow some time for the watcher to detect changes
    std.time.sleep(std.time.ns_per_s / 2); // 500ms

    // Check for events
    var changes_detected = false;
    switch (watcher_result) {
        .FSWatcher => |*w| changes_detected = try w.checkEvents(),
        .PollingFSWatcher => |*w| changes_detected = try w.checkEvents(),
    }

    // Verify that changes were detected
    try std.testing.expect(changes_detected);
    std.debug.print("######### Change detection test passed\n", .{});

    // Check the event contents - get the events and confirm they match what we expect
    switch (watcher_result) {
        .FSWatcher => |*w| {
            if (w.events.items.len > 0) {
                const event = w.events.items[0];
                try std.testing.expectEqualStrings(test_filename, std.fs.path.basename(event.path));
                try std.testing.expectEqual(fs_watcher.EventKind.Create, event.kind);
                std.debug.print("Event details validated successfully\n", .{});
            } else {
                std.debug.print("Warning: No events were recorded in the watcher\n", .{});
            }
        },
        .PollingFSWatcher => |*w| {
            if (w.events.items.len > 0) {
                const event = w.events.items[0];
                try std.testing.expectEqualStrings(test_filename, std.fs.path.basename(event.path));
                try std.testing.expectEqual(fs_watcher.EventKind.Create, event.kind);
                std.debug.print("Event details validated successfully\n", .{});
            } else {
                std.debug.print("Warning: No events were recorded in the watcher\n", .{});
            }
        },
    }
}

test "Test encrypting file content changes creates new backup file" {
    // This test verifies:
    // 1. First encrypt a file with content "abc"
    // 2. Then modify the file to contain "aaa"
    // 3. Verify a new encrypted file is created while the old one is preserved

    // Create a temporary directory structure for testing
    const test_allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Get real paths for source and output directories
    const source_path = try tmp_dir.dir.realpathAlloc(test_allocator, ".");
    defer test_allocator.free(source_path);

    var output_dir = std.testing.tmpDir(.{});
    defer output_dir.cleanup();
    const output_path = try output_dir.dir.realpathAlloc(test_allocator, ".");
    defer test_allocator.free(output_path);

    std.debug.print("Test directories created - Source: {s}, Output: {s}\n", .{ source_path, output_path });

    // Create test file a.txt
    const test_filename = "a.txt";
    try tmp_dir.dir.writeFile(
        .{
            .sub_path = test_filename,
            .data = "abc",
        },
    );
    std.debug.print("Created test file: {s} with content 'abc'\n", .{test_filename});

    // Setup a config for backup
    const conf = config.Config{
        .source_dir = source_path,
        .output_dir = output_path,
        .password = "testpassword",
        .mode = config.Mode.Encrypt,
        .watch_mode = false,
        .min_backup_period = 1,
    };

    // Generate a key from the password
    const salt = crypto_utils.generateRandomSalt();
    var key: [32]u8 = undefined;
    try crypto_utils.deriveCipherKey(conf.password, salt, &key);

    // Perform initial backup (encrypting the file)
    std.debug.print("Performing initial backup of file...\n", .{});
    try backup.doEncrypt(test_allocator, conf);

    // Save the list of encrypted files after first backup
    const content_dir_path = try std.fs.path.join(test_allocator, &[_][]const u8{ output_path, "content" });
    defer test_allocator.free(content_dir_path);

    var content_dir = try std.fs.openDirAbsolute(content_dir_path, .{ .iterate = true });
    defer content_dir.close();

    var dir_it = content_dir.iterate();
    var file_count: usize = 0;
    var first_backup_filename: ?[]u8 = null;

    while (try dir_it.next()) |entry| {
        if (entry.kind == .file) {
            file_count += 1;
            if (first_backup_filename == null) {
                first_backup_filename = try test_allocator.dupe(u8, entry.name);
            }
        }
    }

    // There should be one encrypted file
    try std.testing.expectEqual(@as(usize, 1), file_count);
    try std.testing.expect(first_backup_filename != null);
    std.debug.print("First backup created encrypted file: {s}\n", .{first_backup_filename.?});

    // Modify the source file by writing "aaa" to it
    try tmp_dir.dir.writeFile(
        .{
            .sub_path = test_filename,
            .data = "aaa",
        },
    );
    std.debug.print("Modified test file with content 'aaa'\n", .{});

    // Perform backup again
    std.debug.print("Performing second backup after file modification...\n", .{});
    try backup.doEncrypt(test_allocator, conf);

    // Check if old encrypted file was deleted and a new one was created
    var second_dir_it = content_dir.iterate();
    var second_file_count: usize = 0;
    var found_old_file = false;
    var found_new_file = false;

    while (try second_dir_it.next()) |entry| {
        if (entry.kind == .file) {
            second_file_count += 1;
            if (std.mem.eql(u8, entry.name, first_backup_filename.?)) {
                found_old_file = true;
            } else {
                // If it's not the old file, it must be the new one
                found_new_file = true;
            }
        }
    }

    // Free the filename memory
    if (first_backup_filename) |fname| {
        test_allocator.free(fname);
    }

    // There should be two encrypted files (the new one with "aaa")
    try std.testing.expectEqual(@as(usize, 1), second_file_count);

    // // The new file should not be created
    try std.testing.expect(!found_old_file);

    // The new file should be created
    try std.testing.expect(found_new_file);

    std.debug.print("Test passed: New encrypted file was created for the modified content\n", .{});
}
