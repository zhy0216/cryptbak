# Cryptbak Security Design

## Overview

This document describes the security architecture and encryption implementation for the Cryptbak backup system. Cryptbak is designed to provide secure, encrypted backups with strong cryptographic guarantees while maintaining usability.

## Security Goals

1. **Confidentiality**: All backed-up content is encrypted to prevent unauthorized access
2. **Integrity**: Detect tampering or corruption of backup data
3. **Availability**: Ensure backups can be reliably restored when needed
4. **Authentication**: Only users with the correct password can access the backups

## Cryptographic Primitives

### Key Derivation

- **Algorithm**: PBKDF2 with HMAC-SHA256
- **Iterations**: 100,000 rounds
- **Salt**: 16 bytes, randomly generated
- **Output**: 32-byte (256-bit) key

Cryptbak uses PBKDF2 with HMAC-SHA256 for key derivation from the user's password. The high iteration count (100,000) provides resistance against brute force attacks by making each password guess computationally expensive.

```zig
pub fn deriveCipherKey(password: []const u8, salt: [16]u8, key: *[32]u8) !void {
    try crypto.pwhash.pbkdf2(key, password, &salt, 100000, crypto.auth.hmac.sha2.HmacSha256);
}
```

### Encryption

- **Algorithm**: ChaCha20 stream cipher (IETF version)
- **Key**: 32 bytes (256 bits)
- **Nonce**: 12 bytes, randomly generated for each file
- **Counter**: Incremented for each 8KB block in a file

Cryptbak uses the ChaCha20 stream cipher for encrypting file content. ChaCha20 is a modern, secure stream cipher designed by Daniel J. Bernstein, which offers good performance on a variety of hardware platforms and has strong security properties.

```zig
pub fn encrypt(dst: []u8, src: []const u8, counter: u32, key: [32]u8, nonce: [12]u8) void {
    crypto.stream.chacha.ChaCha20IETF.xor(dst, src, counter, key, nonce);
}
```

### Content Integrity

- **Algorithm**: SHA-256
- **Output**: 32-byte (256-bit) hash

File content is hashed using SHA-256 to create a unique identifier for each file based on its content. This enables content-addressed storage and serves as an integrity check.

## System Architecture

### Master Key and Key Separation

Currently, Cryptbak uses a single derived key for both metadata and content encryption. A potential improvement would be to implement key separation as follows:

1. A master key derived from the user password using PBKDF2
2. Separate keys derived from the master key for:
   - Metadata encryption
   - File content encryption
   - Potential future authentication

Key separation would enhance security by limiting the impact of a key compromise and adhering to the principle of least privilege.

### Metadata Security

The metadata file (`.cryptbak.meta`) contains critical information about the backup, including:

1. File paths
2. Last modified timestamps 
3. File sizes
4. Content hashes
5. Directory flags

The metadata file is encrypted using the same ChaCha20 algorithm as the content, protecting the file structure and names from unauthorized access. The metadata includes:

- A cleartext marker ("CRYPTBAK")
- Unencrypted header with:
  - File format version
  - Timestamp
  - Key salt (16 bytes)
  - Nonce (12 bytes)
- Encrypted metadata section

The metadata nonce is stored with each backup and is preserved between backup operations to maintain consistency.

### Content Encryption

Files are stored in a content-addressed manner, with filenames derived from the SHA-256 hash of their contents:

1. Each file's content is hashed using SHA-256
2. The hash is converted to a hexadecimal string to create a filename
3. The file is encrypted using ChaCha20 with:
   - The derived key
   - A random 12-byte nonce (stored at the beginning of the encrypted file)
   - A counter that increments for each 8KB block

By using content-addressed storage, Cryptbak achieves natural deduplication, as identical files will have the same content hash and be stored only once.

### Path Encryption

Cryptbak encrypts the entire metadata structure (including paths) as a whole. This approach has trade-offs:

**Advantages:**
- Simpler implementation
- No filename length limitations
- No need for per-directory initialization vectors
- Protected directory structure

**Disadvantages:**
- Cannot browse the backup structure without decrypting the metadata
- Must decrypt the entire metadata to access any file information

### Threat Model

Cryptbak protects against the following threats:

1. **Unauthorized access to backups**: All content and metadata are encrypted
2. **Password guessing**: PBKDF2 with 100,000 iterations makes brute-force attacks computationally expensive
3. **Tampering**: Content hashes provide integrity verification
4. **Metadata disclosure**: File structure, names, and sizes are encrypted

### Security Limitations

Cryptbak does not currently protect against:

1. **Side-channel attacks**: No specific mitigations for timing or power analysis attacks
2. **Password strength**: User must choose a strong password; no password strength enforcement
3. **Forward secrecy**: Changing the password doesn't re-encrypt existing backups
4. **Key management**: No key rotation functionality
5. **Authenticated encryption**: Lacks integrated authentication tags for encrypted content

## Implementation Details

### Key Usage

1. **Password**: Provided by the user, used with PBKDF2 to derive the encryption key
2. **Salt**: 16 random bytes, stored in the metadata file header
3. **Derived Key**: 32-byte key used for all encryption/decryption operations
4. **Nonces**: 
   - Metadata nonce: 12 random bytes, stored in metadata file header
   - Content nonces: 12 random bytes, stored at the beginning of each encrypted file

All cryptographic operations use the standard library's implementation of cryptographic primitives, avoiding hand-rolled cryptography.

### Secure Development Practices

1. **No key reuse**: Each file has its own nonce, preventing key-nonce pair reuse
2. **No fixed secrets**: All cryptographic material is either derived or randomly generated
3. **Constant-time operations**: Using library implementations that aim to be constant-time
4. **Explicit memory management**: Memory containing sensitive data is managed carefully

## Future Improvements

1. **Authenticated Encryption**: Add AEAD (Authenticated Encryption with Associated Data) using ChaCha20-Poly1305 to detect tampering
2. **Key separation**: Derive separate keys for metadata and content encryption
3. **Key rotation**: Implement secure key rotation capability
4. **Backup versioning**: Store multiple versions of files with separate encryption keys
5. **Multi-factor authentication**: Support additional authentication factors
6. **Memory security**: Implement secure memory handling for sensitive data
7. **Metadata format hardening**: Add authentication tags for metadata blocks to detect tampering
8. **Switch to scrypt or Argon2**: Consider stronger password hashing algorithms than PBKDF2 for key derivation

## References

1. [ChaCha20 and Poly1305 for IETF Protocols](https://tools.ietf.org/html/rfc8439)
2. [PBKDF2 Specification](https://tools.ietf.org/html/rfc8018#section-5.2)
3. [SHA-256 Specification](https://csrc.nist.gov/publications/detail/fips/180/4/final)
4. [gocryptfs Cryptography](https://nuetzlich.net/gocryptfs/forward_mode_crypto/)
5. [Argon2 Password Hashing](https://github.com/P-H-C/phc-winner-argon2)
