# Security design

TOTP keys grant the ability to generate valid login codes. This application processes them locally and has no telemetry, account service, network client, clipboard integration or background process. Building the project downloads Rust dependencies; running the CLI does not need network access.

## Implemented protections

- Secrets are redacted in the portable model's `Debug` implementation. CLI previews never serialize the full account model, and parser errors omit input values.
- Owned secret bytes, passwords, derived encryption keys and main plaintext import/export buffers use `zeroize` to wipe them on drop. This does **not** guarantee that every copy in third-party parsers, QR/image buffers, allocators, swap or operating-system caches is erased.
- Encrypted bundles use RustCrypto's Argon2id and XChaCha20-Poly1305 implementations, with random salts and nonces. The header is authenticated and the KDF cost is fixed by the format version.
- Unix outputs are created with owner-only permissions. File writes use a temporary file in the destination directory followed by a no-replace persist. Output symlinks are refused. Windows inherits the parent directory's ACL.
- QR payloads are fully rendered before creating a new output directory. Ordinary write failures trigger cleanup; an abrupt process or machine failure can still leave a partial directory.
- Imports enforce file, image and account-count limits. Unsupported entries, malformed input, missing batch parts and conversions that would change TOTP parameters fail before export.

## Boundaries

This is an initial implementation, not an independently audited security product. It does not protect against malware, a compromised operating system, a malicious process running as the same user, screenshots of QR images, weak bundle passwords or disclosure of plaintext exports. Temporary-file deletion is not a secure erase guarantee on modern filesystems.

Use a strong unique bundle password and a private working directory. Treat plaintext JSON, URI files, QR images, password files and screenshots as credentials. Verify that the destination app generates working codes before removing the original accounts. Do not commit real exports even to a private repository; `.gitignore` only provides a convenience filter for common filenames and directories.

Tests use synthetic public keys and RFC 6238 vectors. No personal authenticator data is included in the repository. Reproduce bugs with similarly synthetic accounts, and do not attach real account exports or passwords to issue reports.
