use std::{fmt, str::FromStr};

use data_encoding::{BASE32, BASE32_NOPAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// A decoded TOTP key. Debug output is redacted; owned bytes are wiped on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub fn from_base32(value: &str) -> Result<Self> {
        let normalized = Zeroizing::new(
            value
                .chars()
                .filter(|c| !c.is_ascii_whitespace())
                .map(|c| c.to_ascii_uppercase())
                .collect::<String>(),
        );
        if normalized.len() > 2048 {
            return Err(Error::Invalid("TOTP secret is too long"));
        }
        let encoding = if normalized.contains('=') {
            BASE32
        } else {
            BASE32_NOPAD
        };
        let decoded = encoding
            .decode(normalized.as_bytes())
            .map_err(|_| Error::Invalid("TOTP secret must be valid Base32"))?;
        Self::from_bytes(decoded)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() || bytes.len() > 1024 {
            return Err(Error::Invalid("TOTP secret must contain 1 to 1024 bytes"));
        }
        Ok(Self(bytes))
    }

    /// This explicitly exposes the key; callers must protect the returned data.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_base32(&self) -> Zeroizing<String> {
        Zeroizing::new(BASE32_NOPAD.encode(self.as_bytes()))
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_base32())
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let encoded = Zeroizing::new(String::deserialize(deserializer)?);
        Self::from_base32(&encoded).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        })
    }
}

impl FromStr for Algorithm {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_uppercase().as_str() {
            "SHA1" | "SHA-1" => Ok(Self::Sha1),
            "SHA256" | "SHA-256" => Ok(Self::Sha256),
            "SHA512" | "SHA-512" => Ok(Self::Sha512),
            _ => Err(Error::Invalid(
                "unsupported algorithm; only SHA1, SHA256 and SHA512 are supported",
            )),
        }
    }
}

/// Validated, portable TOTP parameters. App-specific icons and groups are excluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "AccountFields")]
pub struct Account {
    name: String,
    issuer: String,
    secret: Secret,
    algorithm: Algorithm,
    digits: u32,
    period: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountFields {
    name: String,
    issuer: String,
    secret: Secret,
    algorithm: Algorithm,
    digits: u32,
    period: u32,
}

impl TryFrom<AccountFields> for Account {
    type Error = Error;
    fn try_from(value: AccountFields) -> Result<Self> {
        Self::new(
            value.name,
            value.issuer,
            value.secret,
            value.algorithm,
            value.digits,
            value.period,
        )
    }
}

impl Account {
    pub fn new(
        name: String,
        issuer: String,
        secret: Secret,
        algorithm: Algorithm,
        digits: u32,
        period: u32,
    ) -> Result<Self> {
        if name.trim().is_empty() && issuer.trim().is_empty() {
            return Err(Error::Invalid("an account needs a name or issuer"));
        }
        if name.len() > 1024
            || issuer.len() > 1024
            || name.chars().chain(issuer.chars()).any(char::is_control)
        {
            return Err(Error::Invalid(
                "account names and issuers must be at most 1024 bytes and contain no control characters",
            ));
        }
        if !(6..=8).contains(&digits) {
            return Err(Error::Invalid(
                "only 6, 7 and 8 digit TOTP accounts are supported",
            ));
        }
        if !(1..=86_400).contains(&period) {
            return Err(Error::Invalid(
                "TOTP period must be between 1 and 86400 seconds",
            ));
        }
        Ok(Self {
            name,
            issuer,
            secret,
            algorithm,
            digits,
            period,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn secret(&self) -> &Secret {
        &self.secret
    }
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    pub fn digits(&self) -> u32 {
        self.digits
    }
    pub fn period(&self) -> u32 {
        self.period
    }
}
