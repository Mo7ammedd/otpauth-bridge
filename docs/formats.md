# Format notes

The portable account model contains `name`, `issuer`, decoded `secret`, `algorithm`, `digits` and `period`. No current OTP codes or app-specific presentation data are stored. Imports fail as a whole when an entry cannot be represented.

## Standard key URIs

Based on the [Google Authenticator Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format). Accepted fields are `secret`, `issuer`, `algorithm`, `digits` and `period`. Defaults are SHA1, 6 digits and 30 seconds. Unknown or duplicate query fields, conflicting issuers, HOTP, invalid Base32 and invalid parameters are errors. Base32 accepts ASCII whitespace, lowercase text and valid RFC 4648 padding, then exports uppercase without padding.

## Google migration

Based on the [migration protobuf schema used by Aegis](https://github.com/beemdevelopment/Aegis/blob/master/app/src/main/proto/google_auth.proto). The protobuf types are derived with `prost`; no `protoc` installation is required.

| Field | Number | Interpretation |
| --- | --- | --- |
| `otp_parameters` | 1 | Repeated account messages |
| `version` | 2 | Must be 1 |
| `batch_size` | 3 | Number of QR parts; 0 is accepted as a single-part default |
| `batch_index` | 4 | Zero-based part index |
| `batch_id` | 5 | Identifies a multipart export |

Account fields are secret bytes (1), name (2), issuer (3), algorithm enum (4), digit enum (5), type enum (6) and counter (7). SHA1/SHA256/SHA512 are 1/2/3, 6/8 digits are 1/2, and TOTP is type 2. Unspecified or unknown algorithms/digits and non-TOTP types are rejected. TOTP entries with a nonzero counter are rejected.

The payload is Base64 inside the URI's `data` query parameter. Standard and URL-safe Base64, with or without padding, are accepted. Unescaped `+` from some exporters is recovered. The exporter percent-encodes standard Base64 and creates fresh batch IDs using system randomness.

There is no period field in this schema. Accounts imported from it use 30 seconds; exports require that period. Multipart inputs are validated together and require every index exactly once. Standard single-account QRs have no batch metadata, so the tool cannot detect if an independent image was omitted.

## Aegis

Plain backups use outer file version 1 and an empty encryption header (`slots` and `params` are null). The `db` object contains a version and `entries`. Entries use `type: "totp"`, `name`, `issuer` and `info` with `secret`, `algo`, `digits` and `period`.

The exporter creates database version 3 with fresh UUIDs, empty groups, null icons, and empty notes. Database versions 1–3 are imported. Encrypted headers or a string-valued database are rejected with instructions to export plain JSON in Aegis.

References: [VaultFile](https://github.com/beemdevelopment/Aegis/blob/master/app/src/main/java/com/beemdevelopment/aegis/vault/VaultFile.java), [Vault](https://github.com/beemdevelopment/Aegis/blob/master/app/src/main/java/com/beemdevelopment/aegis/vault/Vault.java), [VaultEntry](https://github.com/beemdevelopment/Aegis/blob/master/app/src/main/java/com/beemdevelopment/aegis/vault/VaultEntry.java).

## 2FAS

Plain backups use `schemaVersion` and a `services` array. Each service supplies `secret` and an `otp` object containing account name, issuer, algorithm, digits, period and token type. Null or missing algorithm/digits/period/token type use the standard TOTP defaults. Account selection is `otp.account`, then `otp.label`, then service `name`. A missing issuer falls back to the service name; an explicitly empty issuer is retained.

The exporter writes schema version 4 and includes nullable presentation fields expected by the Android serializer, service ordering and timestamps. `servicesEncrypted` and `reference` are null. Imports support versions 1–4 and reject encrypted backups, HOTP and Steam.

References: [BackupContent](https://github.com/twofas/2fas-android/blob/main/data/services/src/main/java/com/twofasapp/data/services/domain/BackupContent.kt), [BackupService](https://github.com/twofas/2fas-android/blob/main/data/services/src/main/java/com/twofasapp/data/services/domain/BackupService.kt), [ServiceMapper](https://github.com/twofas/2fas-android/blob/main/data/services/src/main/java/com/twofasapp/data/services/mapper/ServiceMapper.kt).

## Encrypted bundle v1

The `.otpb` format is specific to `otpauth-bridge` and does not import directly into an authenticator.

| Offset | Length | Contents |
| --- | --- | --- |
| 0 | 8 | ASCII `OTPBRDG` followed by byte `0x01` |
| 8 | 16 | Random Argon2id salt |
| 24 | 24 | Random XChaCha20 nonce |
| 48 | Remaining | Encrypted UTF-8 JSON followed by a 16-byte Poly1305 tag |

Key derivation is Argon2id version 0x13, 65536 KiB memory, 3 iterations, 1 lane, with a 32-byte output. Passwords are used as exact UTF-8 bytes without Unicode normalization. Parameters are fixed for this version and are not controlled by the file.

The entire 48-byte header is authenticated as associated data. The plaintext is `{"version":1,"accounts":[...]}` using the portable model and Base32 secrets. The JSON document and account models reject unknown fields. Wrong passwords and authentication failures yield the same generic error. Unknown bundle versions are rejected before key derivation.
