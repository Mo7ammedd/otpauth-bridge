//! Offline migration of TOTP account parameters across authenticator export formats.
//!
//! ```
//! use otpauth_bridge::formats::{InputFormat, OutputFormat, import, export};
//! # fn main() -> otpauth_bridge::Result<()> {
//! let input = b"otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example";
//! let accounts = import(input, InputFormat::Auto, None)?;
//! let aegis_json = export(&accounts, OutputFormat::Aegis, None)?;
//! assert!(!aegis_json.is_empty());
//! # Ok(())
//! # }
//! ```

pub mod bundle;
mod error;
pub mod formats;
mod model;
pub mod qr;

pub use error::{Error, Result};
pub use model::{Account, Algorithm, Secret};

pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ACCOUNTS: usize = 10_000;
