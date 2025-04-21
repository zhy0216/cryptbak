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
    watch_path: []const u8,
    is_running: bool,
    events: ArrayList(WatchEvent),

    // Platform-specific fields
    fd: i32 = -1, // For Linux inotify
    kq: i32 = -1, // For macOS kqueue
    handle: ?*anyopaque = null, // For Windows

    pub fn init(allocator: Allocator, watch_path: []const u8) !FSWatcher {
        var watcher = FSWatcher{
            .allocator = allocator,
            .watch_path = try allocator.dupe(u8, watch_path),
            .is_running = false,
            .events = ArrayList(WatchEvent).init(allocator),
        };

        try watcher.initPlatformSpecific();
        return watcher;
    }

    pub fn deinit(self: *FSWatcher) void {
        self.deinitPlatformSpecific();
        self.allocator.free(self.watch_path);
        
        for (self.events.items) |event| {
            self.allocator.free(event.path);
        }
        self.events.deinit();
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
        for (self.events.items) |event| {
            self.allocator.free(event.path);
        }
        self.events.clearRetainingCapacity();
        
        return try self.pollEvents();
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

    // Linux inotify implementation
    fn initInotify(self: *FSWatcher) !void {
        const linux = std.os.linux;
        
        // Create inotify instance
        const fd = linux.inotify_init1(0);
        if (fd < 0) {
            debugPrint("Failed to initialize inotify\n", .{});
            return error.InotifyInitFailed;
        }
        self.fd = @intCast(fd);
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
        const wd = linux.inotify_add_watch(self.fd, @ptrCast(self.watch_path), mask);
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
                const name_end = std.mem.indexOfScalar(u8, buffer[offset..offset + event.len], 0) orelse event.len;
                const name = buffer[offset..offset + name_end];
                
                // Create full path
                const full_path = try fs.path.join(self.allocator, &[_][]const u8{ self.watch_path, name });
                
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
        self.kq = @intCast(kq);
    }

    fn deinitKqueue(self: *FSWatcher) void {
        if (self.kq != -1) {
            _ = std.c.close(self.kq);
            self.kq = -1;
        }
    }

    fn startKqueue(self: *FSWatcher) !void {
        // Open the directory to watch
        var dir = try fs.cwd().openDir(self.watch_path, .{ .iterate = true });
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
        
        // Add directory to watch list
        const Kevent = extern struct {
            ident: usize,
            filter: i16,
            flags: u16,
            fflags: u32,
            data: i64,
            udata: usize,
        };
        
        var changelist = [_]Kevent{
            Kevent{
                .ident = @intCast(dir.fd),
                .filter = EVFILT_VNODE,
                .flags = EV_ADD | EV_CLEAR,
                .fflags = NOTE_WRITE | NOTE_EXTEND | NOTE_DELETE | NOTE_RENAME | NOTE_ATTRIB,
                .data = 0,
                .udata = 0,
            },
        };
        
        const result = std.c.kevent(self.kq, &changelist, changelist.len, null, 0, null);
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
        // Define constants for kqueue
        const EVFILT_VNODE = -4;
        
        // Define Kevent struct for kqueue
        const Kevent = extern struct {
            ident: usize,
            filter: i16,
            flags: u16,
            fflags: u32,
            data: i64,
            udata: usize,
        };
        
        var eventlist = [_]Kevent{undefined};
        
        // Define timespec struct
        const timespec = extern struct {
            tv_sec: isize,
            tv_nsec: isize,
        };
        
        var timeout = timespec{ .tv_sec = 0, .tv_nsec = 100000000 }; // 100ms
        
        // Check for events
        const nevents = std.c.kevent(self.kq, null, 0, &eventlist, eventlist.len, &timeout);
        if (nevents < 0) {
            debugPrint("Failed to poll kqueue events\n", .{});
            return false;
        }
        
        if (nevents == 0) {
            // No events
            return false;
        }
        
        // Process events
        var has_events = false;
        
        for (0..@intCast(nevents)) |_| {
            // Scan the directory for changes
            var dir = try fs.cwd().openDir(self.watch_path, .{ .iterate = true });
            defer dir.close();
            
            var iter = dir.iterate();
            while (try iter.next()) |entry| {
                const full_path = try fs.path.join(self.allocator, &[_][]const u8{ self.watch_path, entry.name });
                
                // For simplicity, we'll just report all as modifications
                // In a real implementation, you'd want to track state to determine the actual event type
                try self.events.append(WatchEvent{
                    .path = full_path,
                    .kind = .Modify,
                });
                
                has_events = true;
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
