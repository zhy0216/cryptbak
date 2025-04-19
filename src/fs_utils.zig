const std = @import("std");
const fs = std.fs;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const config = @import("config.zig");
const metadata = @import("metadata.zig");
const crypto_utils = @import("crypto_utils.zig");
const debugPrint = config.debugPrint;

const FileMetadata = metadata.FileMetadata;

pub fn getRelativePath(full_path: []const u8, base_path: []const u8) []const u8 {
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

pub fn scanDirectory(allocator: Allocator, dir_path: []const u8, base_path: []const u8, file_list: *ArrayList(FileMetadata)) !void {
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
            // Skip .git directories (common case for version controlled repos)
            if (std.mem.eql(u8, entry.name, ".git")) {
                debugPrint("Skipping .git directory: {s}\n", .{full_path});
                continue;
            }

            // If it's an empty directory, we need to record it explicitly
            var sub_dir = try fs.cwd().openDir(full_path, .{ .iterate = true });
            var is_empty = true;
            var sub_iter = sub_dir.iterate();
            if (try sub_iter.next()) |_| {
                is_empty = false;
            }
            sub_dir.close();

            if (is_empty) {
                const rel_path = try fs.path.relative(allocator, base_path, full_path);
                defer allocator.free(rel_path);
                const rel_path_dup = try allocator.dupe(u8, rel_path);
                try file_list.append(FileMetadata{
                    .path = rel_path_dup,
                    .last_modified = 0,
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

            const stat = try fs.cwd().statFile(full_path);
            const hash = try crypto_utils.calculateFileHash(full_path);

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
