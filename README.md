# CryptBak
[中文](README_CN.md).

A simple file encryption backup tool written in [Zig](https://ziglang.org/).

This project is developed with the help of [Windsurf](https://www.windsurfrs.com/) and has only been tested on Mac. Use it at your own risk.
## Features

- Securely encrypt your backup files
- Incremental backups (only encrypt new or modified files)
- Secure password-derived keys
- Decrypt and restore functionality
- Support for empty directories and complex directory structures
- Comprehensive file metadata handling

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
   - Calculates a hash value for each file
   - Compares with previous backup metadata (if exists)
   - Only encrypts new or modified files
   - Removes files from backup that no longer exist in source
   - Updates metadata

2. **Decryption Mode**:
   - Reads metadata from the encrypted folder
   - Decrypts all files to the target folder
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

## Testing

The tool includes comprehensive integration tests for various scenarios:
- Simple file encryption/decryption
- Large files (10MB+)
- Multi-level directory structures
- Special filenames with spaces and special characters
- Empty files and directories
- Incremental backup functionality

Run the tests using:
```bash
./test.sh
```
