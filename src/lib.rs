//! Offline migration of TOTP account parameters across authenticator export formats.

pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ACCOUNTS: usize = 10_000;
