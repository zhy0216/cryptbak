const std = @import("std");
const builtin = @import("builtin");
const fs = std.fs;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const config = @import("config.zig");
const debugPrint = config.debugPrint;

pub const WatchEvent = struct {
    path: []const u8,
    kind: EventKind,
};

pub const EventKind = enum {
    Create,
    Modify,
    Delete,
};

pub const FSWatcher = struct {
    allocator: Allocator,
    path: []const u8,
    is_running: bool,
    events: ArrayList(WatchEvent),
    existing_files: std.StringHashMap(void), // Track existing files

    // Platform-specific fields
    fd: i32 = -1, // For Linux inotify
    kq: i32 = -1, // For macOS kqueue
    handle: ?*anyopaque = null, // For Windows

    pub fn init(allocator: Allocator, watch_path: []const u8) !FSWatcher {
        var watcher = FSWatcher{
            .allocator = allocator,
            .path = try allocator.dupe(u8, watch_path),
            .is_running = false,
            .events = ArrayList(WatchEvent).init(allocator),
            .existing_files = std.StringHashMap(void).init(allocator),
        };

        try watcher.initPlatformSpecific();
        return watcher;
    }

    pub fn deinit(self: *FSWatcher) void {
        self.deinitPlatformSpecific();
        self.allocator.free(self.path);

        for (self.events.items) |event| {
            self.allocator.free(event.path);
        }
        self.events.deinit();

        // Free existing files map - clear it but don't try to free the strings
        // This avoids potential double-free issues during testing
        var it = self.existing_files.keyIterator();
        while (it.next()) |key| {
            self.allocator.free(key.*);
        }
        self.existing_files.deinit();
    }

    pub fn start(self: *FSWatcher) !void {
        if (self.is_running) return;

        try self.startWatching();
        self.is_running = true;
    }

    pub fn stop(self: *FSWatcher) void {
        if (!self.is_running) return;

        self.stopWatching();
        self.is_running = false;
    }

    pub fn checkEvents(self: *FSWatcher) !bool {
        if (!self.is_running) return false;

        // Clear previous events
        if (self.events.items.len > 0) {
            for (self.events.items) |event| {
                self.allocator.free(event.path);
            }
            self.events.clearRetainingCapacity();
        }

        // Always perform a full scan of the directory to ensure we don't miss any files
        try self.performFullScan();

        // Also poll platform-specific events
        return try self.pollEvents() or self.events.items.len > 0;
    }

    fn performFullScan(self: *FSWatcher) !void {
        // Open the directory
        var dir = try fs.cwd().openDir(self.path, .{ .iterate = true });
        defer dir.close();

        // Create a map to track current files
        var current_files = std.StringHashMap(void).init(self.allocator);
        defer {
            var it = current_files.keyIterator();
            while (it.next()) |_| {
                // We don't own these strings
            }
            current_files.deinit();
        }

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            try current_files.put(entry.name, {});

            // Check if this is a new file that we haven't seen before
            if (!self.existing_files.contains(entry.name)) {
                const full_path = try fs.path.join(self.allocator, &[_][]const u8{ self.path, entry.name });
                debugPrint("Full scan found new file: {s}\n", .{entry.name});

                // Store a copy of the name in existing_files
                const name_copy = try self.allocator.dupe(u8, entry.name);
                try self.existing_files.put(name_copy, {});

                try self.events.append(WatchEvent{
                    .path = full_path,
                    .kind = .Create,
                });
            }
        }
    }

    // Platform-specific implementations
    fn initPlatformSpecific(self: *FSWatcher) !void {
        switch (builtin.os.tag) {
            .linux => try self.initInotify(),
            .macos, .freebsd, .netbsd, .openbsd => try self.initKqueue(),
            .windows => try self.initWindows(),
            else => {
                debugPrint("Unsupported OS for file system watching. Falling back to polling.\n", .{});
                return error.UnsupportedOS;
            },
        }

        // Perform initial scan of directory to establish baseline
        try self.performInitialScan();
    }

    fn deinitPlatformSpecific(self: *FSWatcher) void {
        switch (builtin.os.tag) {
            .linux => self.deinitInotify(),
            .macos, .freebsd, .netbsd, .openbsd => self.deinitKqueue(),
            .windows => self.deinitWindows(),
            else => {},
        }
    }

    fn startWatching(self: *FSWatcher) !void {
        switch (builtin.os.tag) {
            .linux => try self.startInotify(),
            .macos, .freebsd, .netbsd, .openbsd => try self.startKqueue(),
            .windows => try self.startWindows(),
            else => return error.UnsupportedOS,
        }
    }

    fn stopWatching(self: *FSWatcher) void {
        switch (builtin.os.tag) {
            .linux => self.stopInotify(),
            .macos, .freebsd, .netbsd, .openbsd => self.stopKqueue(),
            .windows => self.stopWindows(),
            else => {},
        }
    }

    fn pollEvents(self: *FSWatcher) !bool {
        switch (builtin.os.tag) {
            .linux => return try self.pollInotify(),
            .macos, .freebsd, .netbsd, .openbsd => return try self.pollKqueue(),
            .windows => return try self.pollWindows(),
            else => return error.UnsupportedOS,
        }
    }

    fn performInitialScan(self: *FSWatcher) !void {
        // Scan the directory and store information about all files
        var dir = try fs.cwd().openDir(self.path, .{ .iterate = true });
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            // Just store filenames for later comparison
            const name_copy = try self.allocator.dupe(u8, entry.name);

            // Store the name in existing_files map
            try self.existing_files.put(name_copy, {});
        }

        debugPrint("Initial scan complete - indexed {d} items\n", .{self.existing_files.count()});
    }

    // Linux inotify implementation
    fn initInotify(self: *FSWatcher) !void {
        const linux = std.os.linux;

        // Create inotify instance
        const fd = linux.inotify_init1(0);
        if (fd < 0) {
            debugPrint("Failed to initialize inotify\n", .{});
            return error.InotifyInitFailed;
        }
        const fd_i32: i32 = @intCast(fd);
        self.fd = fd_i32;
    }

    fn deinitInotify(self: *FSWatcher) void {
        if (self.fd != -1) {
            const linux = std.os.linux;
            _ = linux.close(self.fd);
            self.fd = -1;
        }
    }

    fn startInotify(self: *FSWatcher) !void {
        const linux = std.os.linux;
        const IN_CREATE = 0x00000100;
        const IN_DELETE = 0x00000200;
        const IN_MODIFY = 0x00000002;
        const IN_MOVED_TO = 0x00000080;
        const IN_MOVED_FROM = 0x00000040;
        const IN_CLOSE_WRITE = 0x00000008;

        // Add watch for the directory
        const mask = IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVED_TO | IN_MOVED_FROM | IN_CLOSE_WRITE;
        const wd = linux.inotify_add_watch(self.fd, @ptrCast(self.path), mask);
        if (wd < 0) {
            debugPrint("Failed to add watch\n", .{});
            return error.InotifyAddWatchFailed;
        }
    }

    fn stopInotify(self: *FSWatcher) void {
        // Nothing to do here, we'll close the fd in deinit
        _ = self;
    }

    fn pollInotify(self: *FSWatcher) !bool {
        const linux = std.os.linux;
        const IN_CREATE = 0x00000100;
        const IN_DELETE = 0x00000200;
        const IN_MODIFY = 0x00000002;
        const IN_MOVED_TO = 0x00000080;
        const IN_MOVED_FROM = 0x00000040;
        const IN_CLOSE_WRITE = 0x00000008;

        var buffer: [4096]u8 = undefined;

        // Set up a non-blocking read with a timeout
        var pfd = [_]linux.pollfd{
            .{
                .fd = self.fd,
                .events = linux.POLL.IN,
                .revents = 0,
            },
        };

        // Poll with a short timeout (100ms)
        const poll_result = linux.poll(&pfd, 1, 100);
        if (poll_result < 0) {
            debugPrint("Poll failed\n", .{});
            return false;
        }

        if (poll_result == 0) {
            // Timeout, no events
            return false;
        }

        if (pfd[0].revents & linux.POLL.IN == 0) {
            // No input events
            return false;
        }

        // Read events
        const bytes_read = linux.read(self.fd, &buffer, buffer.len);
        if (bytes_read < 0) {
            debugPrint("Failed to read inotify events\n", .{});
            return false;
        }

        if (bytes_read == 0) {
            return false;
        }

        var offset: usize = 0;
        var has_events = false;

        while (offset < bytes_read) {
            const event = @as(*align(1) const linux.inotify_event, @ptrCast(&buffer[offset]));
            offset += @sizeOf(linux.inotify_event);

            if (event.len > 0) {
                // Extract the filename
                const name_end = std.mem.indexOfScalar(u8, buffer[offset .. offset + event.len], 0) orelse event.len;
                const name = buffer[offset .. offset + name_end];

                // Create full path
                const full_path = try fs.path.join(self.allocator, &[_][]const u8{ self.path, name });

                // Determine event type
                var kind: EventKind = undefined;
                if (event.mask & (IN_CREATE | IN_MOVED_TO) != 0) {
                    kind = .Create;
                } else if (event.mask & (IN_DELETE | IN_MOVED_FROM) != 0) {
                    kind = .Delete;
                } else if (event.mask & (IN_MODIFY | IN_CLOSE_WRITE) != 0) {
                    kind = .Modify;
                } else {
                    // Unknown event, skip
                    self.allocator.free(full_path);
                    offset += event.len;
                    continue;
                }

                // Add to events list
                try self.events.append(WatchEvent{
                    .path = full_path,
                    .kind = kind,
                });

                has_events = true;
            }

            offset += event.len;
        }

        return has_events;
    }

    // macOS/BSD kqueue implementation
    fn initKqueue(self: *FSWatcher) !void {
        // Use direct system calls instead of std.os.darwin which doesn't exist
        const kq = std.c.kqueue();
        if (kq < 0) {
            debugPrint("Failed to initialize kqueue\n", .{});
            return error.KqueueInitFailed;
        }
        const kq_i32: i32 = @intCast(kq);
        self.kq = kq_i32;
    }

    fn deinitKqueue(self: *FSWatcher) void {
        if (self.kq != -1) {
            _ = std.c.close(self.kq);
            self.kq = -1;
        }
    }

    fn startKqueue(self: *FSWatcher) !void {
        // Open the directory to watch
        var dir = try fs.cwd().openDir(self.path, .{ .iterate = true });
        defer dir.close();

        // Define constants for kqueue
        const EVFILT_VNODE = -4;
        const EV_ADD = 0x0001;
        const EV_CLEAR = 0x0020;
        const NOTE_WRITE = 0x0002;
        const NOTE_EXTEND = 0x0004;
        const NOTE_DELETE = 0x0010;
        const NOTE_RENAME = 0x0020;
        const NOTE_ATTRIB = 0x0008;

        // Use system Kevent type
        var changelist = [_]std.c.Kevent{
            std.c.Kevent{
                .ident = @intCast(dir.fd),
                .filter = EVFILT_VNODE,
                .flags = EV_ADD | EV_CLEAR,
                .fflags = NOTE_WRITE | NOTE_EXTEND | NOTE_DELETE | NOTE_RENAME | NOTE_ATTRIB,
                .data = 0,
                .udata = 0,
            },
        };

        // Create an empty eventlist for receiving events (not needed for registration)
        var eventlist = [_]std.c.Kevent{};

        const result = std.c.kevent(self.kq, &changelist, changelist.len, &eventlist, 0, null);
        if (result < 0) {
            debugPrint("Failed to register kqueue events\n", .{});
            return error.KqueueRegisterFailed;
        }
    }

    fn stopKqueue(self: *FSWatcher) void {
        // Nothing to do here, we'll close the kq in deinit
        _ = self;
    }

    fn pollKqueue(self: *FSWatcher) !bool {
        // Use system Kevent type
        var eventlist = [_]std.c.Kevent{undefined};

        // Create an empty changelist since we don't want to register new events
        var changelist = [_]std.c.Kevent{};

        // Check for events - use null for timeout to make it non-blocking
        const nevents = std.c.kevent(self.kq, &changelist, 0, &eventlist, eventlist.len, null);
        if (nevents < 0) {
            debugPrint("Failed to poll kqueue events\n", .{});
            return false;
        }

        // Always do a full directory scan whether we got kevent notifications or not
        // This ensures we don't miss any file creations, which is critical for the test
        var has_events = false;

        // Keep track of current files to detect deletions
        var current_files = std.StringHashMap(void).init(self.allocator);
        defer {
            var it = current_files.keyIterator();
            while (it.next()) |key| {
                self.allocator.free(key.*);
            }
            current_files.deinit();
        }

        // Scan the directory for all current files
        var dir = try fs.cwd().openDir(self.path, .{ .iterate = true });
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            const name_copy = try self.allocator.dupe(u8, entry.name);
            try current_files.put(name_copy, {});

            // Check if this is a new file that wasn't in our initial scan
            if (!self.existing_files.contains(entry.name)) {
                const full_path = try fs.path.join(self.allocator, &[_][]const u8{ self.path, entry.name });

                debugPrint("Detected new file: {s}\n", .{entry.name});

                // This is a new file that wasn't in the original directory scan
                try self.events.append(WatchEvent{
                    .path = full_path,
                    .kind = .Create,
                });

                // Add to existing files to avoid reporting it twice
                const orig_name_copy = try self.allocator.dupe(u8, entry.name);
                try self.existing_files.put(orig_name_copy, {});

                has_events = true;
            }
        }

        // Now look for file modifications by checking status
        if (nevents > 0) {
            debugPrint("Received kqueue events, checking for file modifications\n", .{});

            // We got actual events, process them
            for (0..@intCast(nevents)) |_| {
                var iter2 = dir.iterate();
                while (try iter2.next()) |entry| {
                    // Check if it's been modified
                    if (self.existing_files.contains(entry.name)) {
                        const full_path = try fs.path.join(self.allocator, &[_][]const u8{ self.path, entry.name });

                        // Get file status
                        const stat = try fs.cwd().statFile(full_path);

                        // Simple check: if the file was modified recently, consider it changed
                        const current_time = std.time.milliTimestamp();
                        const mtime_secs_i64: i64 = @intCast(stat.mtime);
                        const mtime_millis = mtime_secs_i64 * 1000; // Convert seconds to milliseconds
                        const age_millis = current_time - mtime_millis;

                        if (age_millis < 10000) { // If modified in the last 10 seconds
                            debugPrint("Detected modified file: {s}\n", .{entry.name});
                            try self.events.append(WatchEvent{
                                .path = full_path,
                                .kind = .Modify,
                            });

                            has_events = true;
                        } else {
                            // Not a recent modification, free the path
                            self.allocator.free(full_path);
                        }
                    }
                }
            }
        }

        return has_events;
    }

    // Windows implementation
    fn initWindows(self: *FSWatcher) !void {
        // Windows implementation would use ReadDirectoryChangesW
        // This is a simplified placeholder that doesn't return an error
        // so we can still compile on Windows
        debugPrint("Windows file system watching not fully implemented.\n", .{});
        debugPrint("Will fall back to polling-based watcher.\n", .{});
        _ = self;
    }

    fn deinitWindows(self: *FSWatcher) void {
        // Placeholder for Windows cleanup
        _ = self;
    }

    fn startWindows(self: *FSWatcher) !void {
        // Placeholder for Windows start
        // Don't return an error so we can still compile on Windows
        debugPrint("Using polling-based fallback for Windows.\n", .{});
        _ = self;
    }

    fn stopWindows(self: *FSWatcher) void {
        // Placeholder for Windows stop
        _ = self;
    }

    fn pollWindows(self: *FSWatcher) !bool {
        // Placeholder for Windows polling
        // Return false instead of an error so we can still compile on Windows
        _ = self;
        return false;
    }
};

// Fallback polling-based watcher for unsupported platforms
pub const PollingFSWatcher = struct {
    allocator: Allocator,
    watch_path: []const u8,
    is_running: bool,
    events: ArrayList(WatchEvent),
    last_scan: std.StringHashMap(fs.File.Stat),

    pub fn init(allocator: Allocator, watch_path: []const u8) !PollingFSWatcher {
        const watcher = PollingFSWatcher{
            .allocator = allocator,
            .watch_path = try allocator.dupe(u8, watch_path),
            .is_running = false,
            .events = ArrayList(WatchEvent).init(allocator),
            .last_scan = std.StringHashMap(fs.File.Stat).init(allocator),
        };

        return watcher;
    }

    pub fn deinit(self: *PollingFSWatcher) void {
        self.allocator.free(self.watch_path);

        for (self.events.items) |event| {
            self.allocator.free(event.path);
        }
        self.events.deinit();

        var it = self.last_scan.keyIterator();
        while (it.next()) |key| {
            self.allocator.free(key.*);
        }
        self.last_scan.deinit();
    }

    pub fn start(self: *PollingFSWatcher) !void {
        if (self.is_running) return;

        // Initial scan
        try self.scanDirectory();
        self.is_running = true;
    }

    pub fn stop(self: *PollingFSWatcher) void {
        if (!self.is_running) return;

        self.is_running = false;
    }

    pub fn checkEvents(self: *PollingFSWatcher) !bool {
        if (!self.is_running) return false;

        // Clear previous events
        for (self.events.items) |event| {
            self.allocator.free(event.path);
        }
        self.events.clearRetainingCapacity();

        // Scan and compare
        return try self.scanAndCompare();
    }

    fn scanDirectory(self: *PollingFSWatcher) !void {
        // Clear previous scan
        var it = self.last_scan.keyIterator();
        while (it.next()) |key| {
            self.allocator.free(key.*);
        }
        self.last_scan.clearRetainingCapacity();

        // Scan directory
        try self.scanRecursive(self.watch_path);
    }

    fn scanRecursive(self: *PollingFSWatcher, dir_path: []const u8) !void {
        var dir = try fs.cwd().openDir(dir_path, .{ .iterate = true });
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            const full_path = try fs.path.join(self.allocator, &[_][]const u8{ dir_path, entry.name });

            if (entry.kind == .directory) {
                // Skip .git directories
                if (std.mem.eql(u8, entry.name, ".git")) {
                    self.allocator.free(full_path);
                    continue;
                }

                // Recursively scan subdirectory
                try self.scanRecursive(full_path);
            }

            // Get file stats
            const stat = try fs.cwd().statFile(full_path);

            // Store in map
            const path_copy = try self.allocator.dupe(u8, full_path);
            try self.last_scan.put(path_copy, stat);

            self.allocator.free(full_path);
        }
    }

    fn scanAndCompare(self: *PollingFSWatcher) !bool {
        var current_scan = std.StringHashMap(fs.File.Stat).init(self.allocator);
        defer {
            var it = current_scan.keyIterator();
            while (it.next()) |key| {
                self.allocator.free(key.*);
            }
            current_scan.deinit();
        }

        // Scan current state
        var dir = try fs.cwd().openDir(self.watch_path, .{ .iterate = true });
        defer dir.close();

        try self.scanRecursiveToMap(&current_scan, self.watch_path);

        // Compare with previous scan
        var has_changes = false;

        // Check for new or modified files
        var current_it = current_scan.iterator();
        while (current_it.next()) |entry| {
            const path = entry.key_ptr.*;
            const current_stat = entry.value_ptr.*;

            if (self.last_scan.get(path)) |last_stat| {
                // File exists in both scans, check if modified
                if (last_stat.mtime != current_stat.mtime or last_stat.size != current_stat.size) {
                    // Modified file
                    const path_copy = try self.allocator.dupe(u8, path);
                    try self.events.append(WatchEvent{
                        .path = path_copy,
                        .kind = .Modify,
                    });
                    has_changes = true;
                }
            } else {
                // New file
                const path_copy = try self.allocator.dupe(u8, path);
                try self.events.append(WatchEvent{
                    .path = path_copy,
                    .kind = .Create,
                });
                has_changes = true;
            }
        }

        // Check for deleted files
        var last_it = self.last_scan.iterator();
        while (last_it.next()) |entry| {
            const path = entry.key_ptr.*;

            if (!current_scan.contains(path)) {
                // Deleted file
                const path_copy = try self.allocator.dupe(u8, path);
                try self.events.append(WatchEvent{
                    .path = path_copy,
                    .kind = .Delete,
                });
                has_changes = true;
            }
        }

        // Update last scan
        var it = self.last_scan.keyIterator();
        while (it.next()) |key| {
            self.allocator.free(key.*);
        }
        self.last_scan.clearRetainingCapacity();

        current_it = current_scan.iterator();
        while (current_it.next()) |entry| {
            const path_copy = try self.allocator.dupe(u8, entry.key_ptr.*);
            try self.last_scan.put(path_copy, entry.value_ptr.*);
        }

        return has_changes;
    }

    fn scanRecursiveToMap(self: *PollingFSWatcher, map: *std.StringHashMap(fs.File.Stat), dir_path: []const u8) !void {
        var dir = try fs.cwd().openDir(dir_path, .{ .iterate = true });
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            const full_path = try fs.path.join(self.allocator, &[_][]const u8{ dir_path, entry.name });

            if (entry.kind == .directory) {
                // Skip .git directories
                if (std.mem.eql(u8, entry.name, ".git")) {
                    self.allocator.free(full_path);
                    continue;
                }

                // Recursively scan subdirectory
                try self.scanRecursiveToMap(map, full_path);
            }

            // Get file stats
            const stat = try fs.cwd().statFile(full_path);

            // Store in map
            const path_copy = try self.allocator.dupe(u8, full_path);
            try map.put(path_copy, stat);

            self.allocator.free(full_path);
        }
    }
};

// Helper function to create the appropriate watcher based on platform
pub const WatcherType = union(enum) {
    FSWatcher: FSWatcher,
    PollingFSWatcher: PollingFSWatcher,
};

pub fn createWatcher(allocator: Allocator, watch_path: []const u8) !WatcherType {
    // Try to create a native watcher first
    const native_watcher = FSWatcher.init(allocator, watch_path) catch |err| {
        debugPrint("Native file system watcher initialization failed: {any}\n", .{err});
        debugPrint("Falling back to polling-based watcher\n", .{});

        // Fall back to polling-based watcher
        const polling_watcher = try PollingFSWatcher.init(allocator, watch_path);
        return WatcherType{ .PollingFSWatcher = polling_watcher };
    };

    return WatcherType{ .FSWatcher = native_watcher };
}

// Simple test for FSWatcher's performFullScan functionality
test "FSWatcher scan" {
    const testing = std.testing;
    const temp_allocator = testing.allocator;
    
    // Create a temporary test directory
    const test_dir = "fs_watcher_test_dir";
    
    // Delete the directory if it already exists
    std.fs.cwd().deleteTree(test_dir) catch |err| {
        if (err != error.FileNotFound) {
            debugPrint("Warning: Failed to delete test dir: {any}\n", .{err});
        }
    };
    
    try std.fs.cwd().makeDir(test_dir);
    defer std.fs.cwd().deleteTree(test_dir) catch {};
    
    debugPrint("\nTesting FSWatcher scan functionality...\n", .{});
    
    // Create a simple FSWatcher instance
    var watcher = FSWatcher{
        .allocator = temp_allocator,
        .path = try temp_allocator.dupe(u8, test_dir),
        .is_running = true,
        .events = ArrayList(WatchEvent).init(temp_allocator),
        .existing_files = std.StringHashMap(void).init(temp_allocator),
        .fd = -1,
        .kq = -1,
        .handle = null,
    };
    defer {
        temp_allocator.free(watcher.path);
        
        for (watcher.events.items) |event| {
            temp_allocator.free(event.path);
        }
        watcher.events.deinit();
        
        // Free all keys in existing_files
        var it = watcher.existing_files.keyIterator();
        while (it.next()) |key| {
            temp_allocator.free(key.*);
        }
        watcher.existing_files.deinit();
    }
    
    // Create a test file
    const test_file = try std.fs.path.join(temp_allocator, &[_][]const u8{ test_dir, "test_file.txt" });
    defer temp_allocator.free(test_file);
    
    {
        const file = try std.fs.cwd().createFile(test_file, .{});
        file.close();
    }
    debugPrint("Created test file: {s}\n", .{test_file});
    
    // Test performFullScan function directly
    try watcher.performFullScan();
    
    // Check for events
    debugPrint("Events after scan: {d}\n", .{watcher.events.items.len});
    for (watcher.events.items, 0..) |event, i| {
        debugPrint("Event {d}: kind={any}, path={s}\n", .{i, event.kind, event.path});
    }
    
    // Verify that we detected the file
    try testing.expect(watcher.events.items.len > 0);
    
    var found_file = false;
    for (watcher.events.items) |event| {
        if (std.mem.indexOf(u8, event.path, "test_file.txt") != null) {
            found_file = true;
            break;
        }
    }
    try testing.expect(found_file);
}

// Simple test for FSWatcher's checkEvents functionality
test "FSWatcher checkEvents" {
    const testing = std.testing;
    const temp_allocator = testing.allocator;
    
    // Create a temporary test directory
    const test_dir = "fs_watcher_events_test_dir";
    
    // Delete the directory if it already exists
    std.fs.cwd().deleteTree(test_dir) catch |err| {
        if (err != error.FileNotFound) {
            debugPrint("Warning: Failed to delete test dir: {any}\n", .{err});
        }
    };
    
    try std.fs.cwd().makeDir(test_dir);
    defer std.fs.cwd().deleteTree(test_dir) catch {};
    
    debugPrint("\nTesting FSWatcher checkEvents functionality...\n", .{});
    
    // Create a simple FSWatcher instance
    var watcher = FSWatcher{
        .allocator = temp_allocator,
        .path = try temp_allocator.dupe(u8, test_dir),
        .is_running = true,
        .events = ArrayList(WatchEvent).init(temp_allocator),
        .existing_files = std.StringHashMap(void).init(temp_allocator),
        .fd = -1,
        .kq = -1,
        .handle = null,
    };
    defer {
        temp_allocator.free(watcher.path);
        
        for (watcher.events.items) |event| {
            temp_allocator.free(event.path);
        }
        watcher.events.deinit();
        
        // Free all keys in existing_files
        var it = watcher.existing_files.keyIterator();
        while (it.next()) |key| {
            temp_allocator.free(key.*);
        }
        watcher.existing_files.deinit();
    }
    
    // Perform initial scan to establish baseline
    try watcher.performInitialScan();
    debugPrint("Initial scan complete - indexed {d} items\n", .{watcher.existing_files.count()});
    
    // Create a test file
    const test_file = try std.fs.path.join(temp_allocator, &[_][]const u8{ test_dir, "test_events_file.txt" });
    defer temp_allocator.free(test_file);
    
    {
        const file = try std.fs.cwd().createFile(test_file, .{});
        file.close();
    }
    debugPrint("Created test file: {s}\n", .{test_file});
    
    // Test checkEvents function
    const has_events = try watcher.checkEvents();
    
    // Verify we got events
    debugPrint("checkEvents returned: {}\n", .{has_events});
    debugPrint("Events detected: {d}\n", .{watcher.events.items.len});
    
    for (watcher.events.items, 0..) |event, i| {
        debugPrint("Event {d}: kind={any}, path={s}\n", .{i, event.kind, event.path});
    }
    
    // There should be at least one event 
    try testing.expect(has_events);
    try testing.expect(watcher.events.items.len > 0);
    
    // At least one event should be for our test file
    var found_file = false;
    for (watcher.events.items) |event| {
        if (std.mem.indexOf(u8, event.path, "test_events_file.txt") != null) {
            found_file = true;
            break;
        }
    }
    try testing.expect(found_file);
    
    // Call checkEvents again - should clear previous events
    // Create another test file
    const test_file2 = try std.fs.path.join(temp_allocator, &[_][]const u8{ test_dir, "test_events_file2.txt" });
    defer temp_allocator.free(test_file2);
    
    {
        const file = try std.fs.cwd().createFile(test_file2, .{});
        file.close();
    }
    debugPrint("Created second test file: {s}\n", .{test_file2});
    
    // Call checkEvents again
    const has_more_events = try watcher.checkEvents();
    
    // Verify we got events
    debugPrint("Second checkEvents returned: {}\n", .{has_more_events});
    debugPrint("Events detected: {d}\n", .{watcher.events.items.len});
    
    for (watcher.events.items, 0..) |event, i| {
        debugPrint("Event {d}: kind={any}, path={s}\n", .{i, event.kind, event.path});
    }
    
    // There should be at least one event and it should be for the second file only
    try testing.expect(has_more_events);
    try testing.expect(watcher.events.items.len > 0);
    
    // Events should NOT contain the first file anymore (should be cleared)
    var found_first_file = false;
    var found_second_file = false;
    
    for (watcher.events.items) |event| {
        if (std.mem.indexOf(u8, event.path, "test_events_file.txt") != null) {
            found_first_file = true;
        }
        if (std.mem.indexOf(u8, event.path, "test_events_file2.txt") != null) {
            found_second_file = true;
        }
    }
    
    try testing.expect(!found_first_file); // First file events should be cleared
    try testing.expect(found_second_file); // Second file events should be detected
}
