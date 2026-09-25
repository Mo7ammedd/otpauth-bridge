# otpauth-bridge

[![CI](https://github.com/Mo7ammedd/otpauth-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/Mo7ammedd/otpauth-bridge/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An offline Rust CLI and library for migrating TOTP accounts between authenticator apps. Import an export file or a QR image, preview the accounts, and write a format your next authenticator understands.

`otpauth-bridge` preserves the secret key, issuer, account name, hash algorithm, digit count and time period. It rejects unsupported entries and conversions that would change TOTP parameters. It never uploads account data, silently drops entries, or overwrites an existing output path.

```text
$ otpauth-bridge inspect tests/fixtures/accounts.txt
2 TOTP account(s); secret keys are hidden
  1. GitHub / alice@example.com  [SHA1 · 6 digits · 30s]
  2. Example / bob@example.org  [SHA256 · 8 digits · 60s]
```

## Supported formats

| Format | Import | Export | Details |
| --- | --- | --- | --- |
| Standard `otpauth://totp/` | Yes | Yes | One URI per line; SHA1, SHA256, SHA512 |
| Google Authenticator migration | Yes | Yes | `otpauth-migration://offline?data=…`; complete multipart batches |
| Aegis JSON | Yes | Yes | Unencrypted file v1, database v1–3; writes database v3 |
| 2FAS backup | Yes | Yes | Unencrypted schema v1–4; writes schema v4 |
| PNG / JPEG QR images | Yes | PNG | Standard account QRs or Google migration QRs |
| Encrypted `.otpb` bundle | Yes | Yes | Argon2id + XChaCha20-Poly1305; opened by this tool |

Use individual QR codes for other apps that accept standard TOTP setup codes. Apps that do not expose their secret keys or a compatible export cannot be extracted by this tool. HOTP, Steam, push approvals, passkeys and proprietary token types are outside its scope.

## Install

Install [Rust stable](https://rustup.rs/), then clone the repository with an authenticated GitHub account:

```sh
gh repo clone Mo7ammedd/otpauth-bridge
cd otpauth-bridge
cargo install --path . --locked
otpauth-bridge --help
```

For development, use `cargo run -- <command>` without installing the binary. The repository contains a locked dependency graph, tests and CI for Linux, macOS and Windows.

## Migrate accounts

### Google Authenticator → Aegis

Use Google Authenticator's **Transfer accounts → Export accounts**, and save each export QR as a clear local PNG or JPEG image. Supply every image from the same export together:

```sh
otpauth-bridge inspect google-1.png google-2.png
otpauth-bridge convert google-1.png google-2.png --to aegis --output aegis-import.json
```

Import `aegis-import.json` using Aegis's import screen. If one Google batch part is missing or repeated, conversion stops before writing a file. A text file containing the decoded migration URI works too; there is no need to use an online QR decoder.

### Aegis → 2FAS

Export a **plain / unencrypted JSON backup** from Aegis:

```sh
otpauth-bridge inspect aegis-export.json
otpauth-bridge convert aegis-export.json --to twofas --output accounts.2fas
```

Import `accounts.2fas` through 2FAS's backup import screen. Encrypted app-native Aegis and 2FAS backups must first be exported without password protection inside their original app.

### Any supported export → scannable QR codes

```sh
otpauth-bridge qr accounts.2fas --output qr-transfer
```

The new directory contains `0001.png`, `0002.png`, and so on, plus `index.json` with account metadata and file ordering. Open each PNG locally and scan it with the destination app. The images contain the secret keys; the index does not.

For Google Authenticator's batch import flow:

```sh
otpauth-bridge qr aegis-export.json --kind google --output google-transfer
```

Google migration has no custom-period field and supports only 6 or 8 digits. This target rejects any account whose period is not 30 seconds or whose digit count is 7. Use individual QRs or a file format that retains those settings instead.

### Transfer an encrypted bundle

```sh
# Prompts twice for a new password, with terminal echo disabled.
otpauth-bridge convert aegis-export.json --to bundle --output transfer.otpb

# On the destination machine, enter the bundle password when prompted.
otpauth-bridge inspect transfer.otpb
otpauth-bridge convert transfer.otpb --to twofas --output accounts.2fas
```

New bundle passwords must contain at least 12 characters. For automation, `--password-file` supplies the input bundle password and `--new-password-file` supplies a new output bundle password. Each password file contains one UTF-8 line; an optional final newline is removed. Password values are never passed as CLI arguments.

### Merge exports or choose a source explicitly

```sh
otpauth-bridge convert aegis.json accounts.2fas setup-uris.txt --to bundle --output merged.otpb
otpauth-bridge inspect export.json --from aegis --json
otpauth-bridge convert accounts.2fas --to otpauth --output setup-uris.txt
```

Automatic detection examines content rather than file extensions. Standard URI text files can include blank lines, `#` comments, and a UTF-8 BOM. Duplicate accounts are retained in input order. Encrypted inputs in a single command must share the supplied password.

## Compatibility and data handling

- TOTP secrets, names, issuers, SHA1/SHA256/SHA512, 6–8 digits and periods of 1–86400 seconds are supported. Groups, icons, colors, favorites, notes and app-specific display nicknames are not transferred.
- Unknown standard URI parameters are rejected, including custom encoders and nonzero epoch extensions. An issuer embedded in the URI label must agree with the `issuer` parameter.
- Standard URI/QR export rejects names or issuers containing `:` because the key URI format cannot represent them unambiguously. Aegis, 2FAS and encrypted bundles retain these names.
- Google exports contain up to 10 accounts per batch part. Very large labels or keys may exceed QR capacity; the command fails before creating its output directory. File exports remain available.
- Input and output files are limited to 16 MiB, migrations to 10000 accounts, and QR images to 16 megapixels / 8192 pixels per side. All entries must be valid before an export is written.
- New files use mode `0600` and new QR directories use `0700` on Unix. Windows files inherit the destination directory's ACL. Parent directories must already exist. Existing files, directories and output symlinks are never replaced.
- Parser errors omit secret payloads. `inspect` only reveals metadata. Plain exports and QR images still contain live credentials: keep them outside version control, verify codes in the destination app before removing the source accounts, and remove temporary exports when finished.

Compatibility is covered by tests based on the upstream schemas, independently encoded Google protobuf data, PNG/JPEG decoding and RFC 6238 code vectors. Device import flows and differences between authenticator app versions have **not** been manually tested. See [format references](docs/formats.md) and [security design](SECURITY.md).

## Library

```rust
use otpauth_bridge::formats::{import, export, InputFormat, OutputFormat};

fn main() -> otpauth_bridge::Result<()> {
    let input = b"otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example";
    let accounts = import(input, InputFormat::Auto, None)?;
    let aegis_json = export(&accounts, OutputFormat::Aegis, None)?;
    assert!(!aegis_json.is_empty());
    Ok(())
}
```

Use `formats::Importer` to accumulate multiple inputs before validating Google batch completeness. Secrets redact their `Debug` output and use `zeroize` for their owned key buffers. Export APIs deliberately return sensitive data; callers are responsible for where it goes.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo build --release --locked
```

All committed fixtures use public demonstration keys or RFC test data. Tests cover parameter preservation, all RFC 6238 Appendix B vectors, malformed exports, incomplete Google batches, encrypted bundle authentication, QR decoding, CLI workflows, overwrite protection and Unix file permissions.

Licensed under [MIT](LICENSE).
