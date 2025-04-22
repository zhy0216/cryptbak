const std = @import("std");

const config = @import("config.zig");
const backup = @import("backup.zig");
const fs_watcher = @import("fs_watcher.zig");

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
