use std::collections::{HashMap, HashSet};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use prost::Message;
use rand_core::{OsRng, RngCore};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::{Account, Algorithm, Error, Result, Secret};

/// Google's migration schema has no period field. Never silently replace one.
const ACCOUNTS_PER_QR: usize = 10;
const MAX_BATCH_PARTS: i32 = 1000;

#[derive(Clone, PartialEq, Message)]
struct MigrationPayload {
    #[prost(message, repeated, tag = "1")]
    otp_parameters: Vec<OtpParameters>,
    #[prost(int32, tag = "2")]
    version: i32,
    #[prost(int32, tag = "3")]
    batch_size: i32,
    #[prost(int32, tag = "4")]
    batch_index: i32,
    #[prost(int32, tag = "5")]
    batch_id: i32,
}

#[derive(Clone, PartialEq, Message)]
struct OtpParameters {
    #[prost(bytes = "vec", tag = "1")]
    secret: Vec<u8>,
    #[prost(string, tag = "2")]
    name: String,
    #[prost(string, tag = "3")]
    issuer: String,
    #[prost(int32, tag = "4")]
    algorithm: i32,
    #[prost(int32, tag = "5")]
    digits: i32,
    #[prost(int32, tag = "6")]
    kind: i32,
    #[prost(int64, tag = "7")]
    counter: i64,
}

impl Drop for OtpParameters {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BatchPart {
    id: i32,
    size: i32,
    index: i32,
}

pub(crate) fn decode(uri: &str) -> Result<(Vec<Account>, BatchPart)> {
    if uri
        .chars()
        .any(|c| c.is_ascii_whitespace() || c.is_control())
    {
        return Err(Error::Invalid(
            "migration URI contains unescaped whitespace or control characters",
        ));
    }
    let url = Url::parse(uri).map_err(|_| Error::Invalid("invalid Google migration URI"))?;
    if url.scheme() != "otpauth-migration"
        || url.host_str() != Some("offline")
        || !matches!(url.path(), "" | "/")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Invalid(
            "expected an otpauth-migration://offline?data= URI",
        ));
    }
    let mut data = None;
    for (key, value) in url.query_pairs() {
        if key != "data" || data.is_some() {
            return Err(Error::Invalid(
                "migration URI requires exactly one data parameter",
            ));
        }
        // Some exporters omit percent encoding of '+' in standard Base64.
        data = Some(Zeroizing::new(value.replace(' ', "+")));
    }
    let data = data.ok_or(Error::Invalid(
        "migration URI is missing its data parameter",
    ))?;
    let bytes = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .into_iter()
        .find_map(|engine| engine.decode(data.as_bytes()).ok())
        .map(Zeroizing::new)
        .ok_or(Error::Invalid("migration data must be valid Base64"))?;
    let payload = MigrationPayload::decode(bytes.as_slice())
        .map_err(|_| Error::Invalid("invalid Google migration protobuf payload"))?;
    if payload.version != 1 {
        return Err(Error::Invalid(
            "unsupported Google migration version; expected version 1",
        ));
    }
    // A zero batch size is the protobuf default used by some single-QR exporters.
    let size = if payload.batch_size == 0 {
        1
    } else {
        payload.batch_size
    };
    if !(1..=MAX_BATCH_PARTS).contains(&size) || !(0..size).contains(&payload.batch_index) {
        return Err(Error::Invalid("invalid Google migration batch metadata"));
    }
    if payload.otp_parameters.is_empty() {
        return Err(Error::Invalid("Google migration QR contains no accounts"));
    }
    let accounts = payload
        .otp_parameters
        .iter()
        .enumerate()
        .map(|(index, entry)| convert_entry(entry).map_err(|err| err.entry(index + 1)))
        .collect::<Result<Vec<_>>>()?;
    Ok((
        accounts,
        BatchPart {
            id: payload.batch_id,
            size,
            index: payload.batch_index,
        },
    ))
}

fn convert_entry(entry: &OtpParameters) -> Result<Account> {
    if entry.kind != 2 {
        return Err(Error::Invalid("Google migration contains a non-TOTP entry"));
    }
    let algorithm = match entry.algorithm {
        1 => Algorithm::Sha1,
        2 => Algorithm::Sha256,
        3 => Algorithm::Sha512,
        _ => return Err(Error::Invalid("unsupported Google migration algorithm")),
    };
    let digits = match entry.digits {
        1 => 6,
        2 => 8,
        _ => return Err(Error::Invalid("unsupported Google migration digit count")),
    };
    if entry.counter != 0 {
        return Err(Error::Invalid(
            "TOTP migration entry contains an unexpected counter",
        ));
    }
    let name = entry
        .name
        .strip_prefix(&format!("{}:", entry.issuer))
        .filter(|_| !entry.issuer.is_empty())
        .unwrap_or(&entry.name);
    Account::new(
        name.into(),
        entry.issuer.clone(),
        Secret::from_bytes(entry.secret.clone())?,
        algorithm,
        digits,
        30,
    )
}

pub(crate) fn validate_batches(parts: &[BatchPart]) -> Result<()> {
    let mut groups: HashMap<i32, (i32, HashSet<i32>)> = HashMap::new();
    for part in parts.iter().filter(|p| p.size > 1) {
        let (size, indexes) = groups
            .entry(part.id)
            .or_insert_with(|| (part.size, HashSet::new()));
        if *size != part.size || !indexes.insert(part.index) {
            return Err(Error::Invalid(
                "conflicting or duplicate Google migration batch parts",
            ));
        }
    }
    for (size, indexes) in groups.values() {
        if indexes.len() != *size as usize {
            return Err(Error::IncompleteBatch {
                received: indexes.len(),
                expected: *size as usize,
            });
        }
    }
    Ok(())
}

pub fn encode(accounts: &[Account]) -> Result<Vec<Zeroizing<String>>> {
    if accounts.is_empty() {
        return Err(Error::Invalid("there are no accounts to export"));
    }
    for (index, account) in accounts.iter().enumerate() {
        if account.period() != 30 || !matches!(account.digits(), 6 | 8) {
            return Err(Error::Invalid("Google migration only represents 30-second TOTP with 6 or 8 digits; choose otpauth, Aegis, 2FAS or a bundle").entry(index + 1));
        }
    }
    let batch_size = accounts.len().div_ceil(ACCOUNTS_PER_QR);
    if batch_size > MAX_BATCH_PARTS as usize {
        return Err(Error::Invalid(
            "too many accounts for a Google migration batch",
        ));
    }
    let mut random = [0; 4];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| Error::Invalid("system random number generator is unavailable"))?;
    let batch_id = i32::from_le_bytes(random) & i32::MAX;
    accounts
        .chunks(ACCOUNTS_PER_QR)
        .enumerate()
        .map(|(index, chunk)| {
            let payload = MigrationPayload {
                otp_parameters: chunk
                    .iter()
                    .map(|account| OtpParameters {
                        secret: account.secret().as_bytes().to_vec(),
                        name: if account.issuer().is_empty() {
                            account.name().into()
                        } else {
                            format!("{}:{}", account.issuer(), account.name())
                        },
                        issuer: account.issuer().into(),
                        algorithm: match account.algorithm() {
                            Algorithm::Sha1 => 1,
                            Algorithm::Sha256 => 2,
                            Algorithm::Sha512 => 3,
                        },
                        digits: if account.digits() == 6 { 1 } else { 2 },
                        kind: 2,
                        counter: 0,
                    })
                    .collect(),
                version: 1,
                batch_size: batch_size as i32,
                batch_index: index as i32,
                batch_id,
            };
            let bytes = Zeroizing::new(payload.encode_to_vec());
            let encoded = Zeroizing::new(STANDARD.encode(bytes.as_slice()));
            let mut result = Zeroizing::new(String::from("otpauth-migration://offline?data="));
            for part in
                percent_encoding::utf8_percent_encode(&encoded, percent_encoding::NON_ALPHANUMERIC)
            {
                result.push_str(part);
            }
            Ok(result)
        })
        .collect()
}
