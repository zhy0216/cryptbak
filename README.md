# CryptBak
[中文](README_CN.md)

A simple file encryption backup tool written in [Zig](https://ziglang.org/).

This project is developed with the help of [Windsurf](https://www.windsurfrs.com/) and has only been tested on Mac. Use it at your own risk.
## Features

- Securely encrypt your backup files
- Incremental backups (only encrypt new or modified files)
- Content-based deduplication (identical files are backed up only once)
- Secure password-derived keys
- Decrypt and restore functionality
- Support for empty directories and complex directory structures
- Comprehensive file metadata handling
- Enhanced privacy with filename hashing
- Backup integrity checking to detect and report missing files

## Changelog

### v0.0.8
- Fixed key handling in metadata operations 
- Fixed metadata nonce preservation between backup operations to ensure encryption consistency
- Improved integrity check functionality and reliability

### v0.0.7
- Added integrity check mode (`-c`) to detect missing backup files and update metadata accordingly

### v0.0.6
- Fix file change detection issue in watch mode

### v0.0.4

- **Watch Mode**: Added new watch mode (`-t`) to continuously monitor source directory for changes
- **Minimum Backup Period**: Added support for configurable minimum time between backups (`--mt` option, default 90 seconds)

### v0.0.3 

- **Content-based Deduplication**: Using SHA-256 hash of file contents as backup filenames, automatically deduplicating identical files
- **Smart Deletion**: Checking for other files referencing the same content before deleting backup files

### v0.0.2 

- **Enhanced Security**: All encrypted files are now stored in a `content` subfolder in the backup directory
- **Privacy Protection**: Using MD5 hash of original file paths as encrypted filenames to prevent leaking original names
- **Hidden Directory Structure**: No longer creating original directory structure in backup, all structure info is only saved in encrypted metadata
- **Improved Restore Process**: Decryption first creates the complete directory structure from metadata, then decrypts files
- **Strict Privacy Protection**: Backup directory doesn't contain any identifiable original file or directory information

### v0.0.1

- Initial release
- Basic file encryption backup functionality
- Incremental backup support
- Password-derived key support
- Decrypt and restore functionality

## Requirements

- Zig 0.14.0 or higher

## Building

```bash
git clone https://github.com/zhy0216/cryptbak.git
cd cryptbak
zig build
```

The compiled executable will be located at `./zig-out/bin/cryptbak`.

## Usage

### Encrypting Backup

```bash
./cryptbak source_folder output_folder -p password
```

### Decrypting Restore

```bash
./cryptbak source_folder output_folder -d -p password
```

## How It Works

1. **Encryption Mode**:
   - Scans all files in the source folder
   - Calculates a SHA-256 hash value for each file
   - Compares with previous backup metadata (if exists)
   - Only encrypts new or modified files
   - Uses file content hash as backup filename, automatically deduplicating identical files
   - Updates metadata
   - Stores encrypted files in the `content` directory using content hash as filenames

2. **Decryption Mode**:
   - Reads metadata from the encrypted folder
   - First creates all directory structures according to metadata
   - Retrieves encrypted files from `content` directory and decrypts them to their original locations
   - Recreates the original directory structure, including empty directories

3. **Metadata**:
   - Stored in `.cryptbak.meta` file in the output folder
   - Contains path, modification time, size, and hash for each file
   - The metadata itself is also encrypted with a two-part structure:
     - Unencrypted header (version, timestamp, file count)
     - Encrypted file details section

## Security Details

- Uses ChaCha20IETF stream cipher for encryption
- Keys are derived from passwords using PBKDF2 algorithm
- Each file is encrypted with a unique random nonce
- Includes cryptographic validation markers
- No original filenames are exposed in the backup (filenames are hashed using MD5)
- Directory structure is completely hidden, with all files stored flat in a content folder
- All structural information is only available in the encrypted metadata
