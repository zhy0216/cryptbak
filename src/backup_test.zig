const std = @import("std");
const testing = std.testing;
const fs = std.fs;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const backup = @import("backup.zig");
const metadata = @import("metadata.zig");
const crypto_utils = @import("crypto_utils.zig");
const config = @import("config.zig");

const Config = config.Config;
const BackupMetadata = metadata.BackupMetadata;
const FileMetadata = metadata.FileMetadata;

// Create test file
fn createTestFile(dir: fs.Dir, path: []const u8, content: []const u8) !void {
    var file = try dir.createFile(path, .{});
    defer file.close();
    try file.writeAll(content);
}

// Read file content
fn readFileContent(dir: fs.Dir, path: []const u8, allocator: Allocator) ![]u8 {
    var file = try dir.openFile(path, .{});
    defer file.close();

    const stat = try file.stat();
    const buffer = try allocator.alloc(u8, stat.size);
    const bytes_read = try file.readAll(buffer);

    if (bytes_read != stat.size) {
        allocator.free(buffer);
        return error.IncompleteRead;
    }

    return buffer;
}

// Test handling of duplicate content files
test "backup with duplicate content files" {
    // Create temporary directory
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Get the path of the temporary directory
    const tmp_path = try tmp_dir.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(tmp_path);

    // Create source, backup, and restore directories
    const source_dir_path = try fs.path.join(testing.allocator, &[_][]const u8{ tmp_path, "source" });
    defer testing.allocator.free(source_dir_path);
    try fs.cwd().makePath(source_dir_path);

    const backup_dir_path = try fs.path.join(testing.allocator, &[_][]const u8{ tmp_path, "backup" });
    defer testing.allocator.free(backup_dir_path);
    try fs.cwd().makePath(backup_dir_path);

    const restore_dir_path = try fs.path.join(testing.allocator, &[_][]const u8{ tmp_path, "restore" });
    defer testing.allocator.free(restore_dir_path);
    try fs.cwd().makePath(restore_dir_path);

    // Open source directory
    var source_dir = try fs.cwd().openDir(source_dir_path, .{});
    defer source_dir.close();

    // Create two files with identical content
    const test_content = "This is test content, two files are identical";
    try createTestFile(source_dir, "file1.txt", test_content);
    try createTestFile(source_dir, "file2.txt", test_content);

    // Create a file with different content
    try createTestFile(source_dir, "file3.txt", "This is different content");

    // Create backup configuration
    const source_path = try fs.path.join(testing.allocator, &[_][]const u8{ tmp_path, "source" });
    defer testing.allocator.free(source_path);

    const backup_path = try fs.path.join(testing.allocator, &[_][]const u8{ tmp_path, "backup" });
    defer testing.allocator.free(backup_path);

    const restore_path = try fs.path.join(testing.allocator, &[_][]const u8{ tmp_path, "restore" });
    defer testing.allocator.free(restore_path);

    const test_password = "test_password";

    const backup_config = Config{
        .source_dir = source_path,
        .output_dir = backup_path,
        .password = test_password,
        .mode = .Encrypt,
        .watch_mode = false,
        .min_backup_period = 90,
    };

    // Perform backup
    try backup.doEncrypt(testing.allocator, backup_config);

    // Check the number of files in the backup directory
    const backup_content_path = try fs.path.join(testing.allocator, &[_][]const u8{ backup_path, "content" });
    defer testing.allocator.free(backup_content_path);
    var backup_content_dir = try fs.cwd().openDir(backup_content_path, .{ .iterate = true });
    defer backup_content_dir.close();

    var file_count: usize = 0;
    var it = backup_content_dir.iterate();
    while (try it.next()) |_| {
        file_count += 1;
    }

    // Since there are two files with identical content, the content directory should only have 1 file for them (identical content is backed up only once)
    // Plus one file with different content, there should be 2 files in total
    try testing.expectEqual(@as(usize, 2), file_count);

    // Perform restore
    const restore_config = Config{
        .source_dir = backup_path,
        .output_dir = restore_path,
        .password = test_password,
        .mode = .Decrypt,
        .watch_mode = false,
        .min_backup_period = 90,
    };

    try backup.doDecrypt(testing.allocator, restore_config);

    // Check restored files
    var restore_dir = try fs.cwd().openDir(restore_path, .{});
    defer restore_dir.close();

    // Check if the content of restored files is correct
    const content1 = try readFileContent(restore_dir, "file1.txt", testing.allocator);
    defer testing.allocator.free(content1);
    try testing.expectEqualStrings(test_content, content1);

    const content2 = try readFileContent(restore_dir, "file2.txt", testing.allocator);
    defer testing.allocator.free(content2);
    try testing.expectEqualStrings(test_content, content2);

    const content3 = try readFileContent(restore_dir, "file3.txt", testing.allocator);
    defer testing.allocator.free(content3);
    try testing.expectEqualStrings("This is different content", content3);
}

// Test scenario of deleting duplicate files
test "backup with duplicate content and file deletion" {
    // Create temporary directory
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Get the path of the temporary directory
    const tmp_path = try tmp_dir.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(tmp_path);

    // Create source and backup directories
    const source_dir_path = try fs.path.join(testing.allocator, &[_][]const u8{ tmp_path, "source" });
    defer testing.allocator.free(source_dir_path);
    try fs.cwd().makePath(source_dir_path);

    const backup_dir_path = try fs.path.join(testing.allocator, &[_][]const u8{ tmp_path, "backup" });
    defer testing.allocator.free(backup_dir_path);
    try fs.cwd().makePath(backup_dir_path);

    // Open source directory
    var source_dir = try fs.cwd().openDir(source_dir_path, .{});
    defer source_dir.close();

    // Create two files with identical content
    const test_content = "This is test content, two files are identical";
    try createTestFile(source_dir, "file1.txt", test_content);
    try createTestFile(source_dir, "file2.txt", test_content);

    // Create backup configuration
    const source_path = try fs.path.join(testing.allocator, &[_][]const u8{ tmp_path, "source" });
    defer testing.allocator.free(source_path);

    const backup_path = try fs.path.join(testing.allocator, &[_][]const u8{ tmp_path, "backup" });
    defer testing.allocator.free(backup_path);

    const test_password = "test_password";

    const backup_config = Config{
        .source_dir = source_path,
        .output_dir = backup_path,
        .password = test_password,
        .mode = .Encrypt,
        .watch_mode = false,
        .min_backup_period = 90,
    };

    // Perform first backup
    try backup.doEncrypt(testing.allocator, backup_config);

    // Check the number of files in the backup directory
    const backup_content_path = try fs.path.join(testing.allocator, &[_][]const u8{ backup_path, "content" });
    defer testing.allocator.free(backup_content_path);
    var backup_content_dir = try fs.cwd().openDir(backup_content_path, .{ .iterate = true });
    defer backup_content_dir.close();

    var file_count: usize = 0;
    var it = backup_content_dir.iterate();
    while (try it.next()) |_| {
        file_count += 1;
    }

    // Since there are two files with identical content, the backup directory should only have 1 file
    try testing.expectEqual(@as(usize, 1), file_count);

    // Delete one file
    try source_dir.deleteFile("file1.txt");

    // Perform second backup
    try backup.doEncrypt(testing.allocator, backup_config);

    // Check the number of files in the backup directory again
    const backup_content_path2 = try fs.path.join(testing.allocator, &[_][]const u8{ backup_path, "content" });
    defer testing.allocator.free(backup_content_path2);
    var backup_content_dir2 = try fs.cwd().openDir(backup_content_path2, .{ .iterate = true });
    defer backup_content_dir2.close();

    var file_count2: usize = 0;
    var it2 = backup_content_dir2.iterate();
    while (try it2.next()) |_| {
        file_count2 += 1;
    }

    // Since file2.txt still references the same content, the backup file should not be deleted
    try testing.expectEqual(@as(usize, 1), file_count2);

    // Delete the second file
    try source_dir.deleteFile("file2.txt");

    // Perform third backup
    try backup.doEncrypt(testing.allocator, backup_config);

    // Check the number of files in the backup directory again
    const backup_content_path3 = try fs.path.join(testing.allocator, &[_][]const u8{ backup_path, "content" });
    defer testing.allocator.free(backup_content_path3);
    var backup_content_dir3 = try fs.cwd().openDir(backup_content_path3, .{ .iterate = true });
    defer backup_content_dir3.close();

    var file_count3: usize = 0;
    var it3 = backup_content_dir3.iterate();
    while (try it3.next()) |_| {
        file_count3 += 1;
    }

    // Now all files referencing this content have been deleted, the backup file should also be deleted
    try testing.expectEqual(@as(usize, 0), file_count3);
}

// Test scenario with multiple files referencing the same content
test "backup with multiple files referencing same content" {
    // Create temporary directory
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Get the path of the temporary directory
    const tmp_path = try tmp_dir.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(tmp_path);

    // Create source and backup directories
    const source_dir_path = try fs.path.join(testing.allocator, &[_][]const u8{ tmp_path, "source" });
    defer testing.allocator.free(source_dir_path);
    try fs.cwd().makePath(source_dir_path);

    const backup_dir_path = try fs.path.join(testing.allocator, &[_][]const u8{ tmp_path, "backup" });
    defer testing.allocator.free(backup_dir_path);
    try fs.cwd().makePath(backup_dir_path);

    // Open source directory
    var source_dir = try fs.cwd().openDir(source_dir_path, .{});
    defer source_dir.close();

    // Create multiple files with identical content
    const test_content = "This is test content, multiple files are identical";
    try createTestFile(source_dir, "file1.txt", test_content);
    try createTestFile(source_dir, "file2.txt", test_content);
    try createTestFile(source_dir, "file3.txt", test_content);
    try createTestFile(source_dir, "file4.txt", test_content);
    try createTestFile(source_dir, "file5.txt", test_content);

    // Create backup configuration
    const source_path = try fs.path.join(testing.allocator, &[_][]const u8{ tmp_path, "source" });
    defer testing.allocator.free(source_path);

    const backup_path = try fs.path.join(testing.allocator, &[_][]const u8{ tmp_path, "backup" });
    defer testing.allocator.free(backup_path);

    const test_password = "test_password";

    const backup_config = Config{
        .source_dir = source_path,
        .output_dir = backup_path,
        .password = test_password,
        .mode = .Encrypt,
        .watch_mode = false,
        .min_backup_period = 90,
    };

    // Perform backup
    try backup.doEncrypt(testing.allocator, backup_config);

    // Check the number of files in the backup directory
    const backup_content_path = try fs.path.join(testing.allocator, &[_][]const u8{ backup_path, "content" });
    defer testing.allocator.free(backup_content_path);
    var backup_content_dir = try fs.cwd().openDir(backup_content_path, .{ .iterate = true });
    defer backup_content_dir.close();

    var file_count: usize = 0;
    var it = backup_content_dir.iterate();
    while (try it.next()) |_| {
        file_count += 1;
    }

    // Despite having 5 files with identical content, the backup directory should only have 1 file
    try testing.expectEqual(@as(usize, 1), file_count);

    // Delete some files
    try source_dir.deleteFile("file1.txt");
    try source_dir.deleteFile("file2.txt");
    try source_dir.deleteFile("file3.txt");

    // Perform second backup
    try backup.doEncrypt(testing.allocator, backup_config);

    // Check the number of files in the backup directory again
    const backup_content_path2 = try fs.path.join(testing.allocator, &[_][]const u8{ backup_path, "content" });
    defer testing.allocator.free(backup_content_path2);
    var backup_content_dir2 = try fs.cwd().openDir(backup_content_path2, .{ .iterate = true });
    defer backup_content_dir2.close();

    var file_count2: usize = 0;
    var it2 = backup_content_dir2.iterate();
    while (try it2.next()) |_| {
        file_count2 += 1;
    }

    // Since file4.txt and file5.txt still reference the same content, the backup file should not be deleted
    try testing.expectEqual(@as(usize, 1), file_count2);

    // Delete remaining files
    try source_dir.deleteFile("file4.txt");
    try source_dir.deleteFile("file5.txt");

    // Perform third backup
    try backup.doEncrypt(testing.allocator, backup_config);

    // Check the number of files in the backup directory again
    const backup_content_path3 = try fs.path.join(testing.allocator, &[_][]const u8{ backup_path, "content" });
    defer testing.allocator.free(backup_content_path3);
    var backup_content_dir3 = try fs.cwd().openDir(backup_content_path3, .{ .iterate = true });
    defer backup_content_dir3.close();

    var file_count3: usize = 0;
    var it3 = backup_content_dir3.iterate();
    while (try it3.next()) |_| {
        file_count3 += 1;
    }

    // Now all files referencing this content have been deleted, the backup file should also be deleted
    try testing.expectEqual(@as(usize, 0), file_count3);
}
