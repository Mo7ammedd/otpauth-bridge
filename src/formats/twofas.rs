use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Account, Algorithm, Error, Result, Secret};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InputFile {
    schema_version: u32,
    services_encrypted: Option<String>,
    reference: Option<String>,
    #[serde(default)]
    services: Vec<InputService>,
}

#[derive(Deserialize)]
struct InputService {
    name: String,
    secret: Secret,
    otp: InputOtp,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InputOtp {
    account: Option<String>,
    issuer: Option<String>,
    label: Option<String>,
    algorithm: Option<String>,
    digits: Option<u32>,
    period: Option<u32>,
    token_type: Option<String>,
    counter: Option<u64>,
}

pub fn decode(bytes: &[u8]) -> Result<Vec<Account>> {
    let file: InputFile = serde_json::from_slice(bytes)?;
    if !(1..=4).contains(&file.schema_version) {
        return Err(Error::Invalid(
            "unsupported 2FAS schema version; expected version 1 through 4",
        ));
    }
    if file.services_encrypted.is_some() || file.reference.is_some_and(|value| !value.is_empty()) {
        return Err(Error::Invalid(
            "encrypted 2FAS backups are not supported; export a backup without password protection from 2FAS first",
        ));
    }
    file.services
        .into_iter()
        .enumerate()
        .map(|(index, entry)| convert_entry(entry).map_err(|err| err.entry(index + 1)))
        .collect()
}

fn convert_entry(entry: InputService) -> Result<Account> {
    if entry
        .otp
        .token_type
        .as_deref()
        .is_some_and(|kind| kind != "TOTP")
    {
        return Err(Error::Invalid("2FAS backup contains a non-TOTP entry"));
    }
    if entry.otp.counter.is_some_and(|value| value != 0) {
        return Err(Error::Invalid(
            "2FAS TOTP entry contains an unexpected counter",
        ));
    }
    let issuer = entry.otp.issuer.unwrap_or_else(|| entry.name.clone());
    let name = entry.otp.account.or(entry.otp.label).unwrap_or(entry.name);
    let algorithm = entry
        .otp
        .algorithm
        .as_deref()
        .map(str::parse)
        .transpose()?
        .unwrap_or(Algorithm::Sha1);
    Account::new(
        name,
        issuer,
        entry.secret,
        algorithm,
        entry.otp.digits.unwrap_or(6),
        entry.otp.period.unwrap_or(30),
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OutputFile<'a> {
    schema_version: u32,
    services: Vec<OutputService<'a>>,
    groups: Vec<()>,
    updated_at: u64,
    app_origin: &'static str,
    app_version_code: u32,
    app_version_name: &'static str,
    services_encrypted: Option<()>,
    reference: Option<()>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OutputService<'a> {
    name: &'a str,
    secret: &'a Secret,
    updated_at: u64,
    #[serde(rename = "serviceTypeID")]
    service_type_id: Option<()>,
    otp: OutputOtp<'a>,
    order: Order,
    badge: Option<()>,
    icon: Option<()>,
    group_id: Option<()>,
}

#[derive(Serialize)]
struct Order {
    position: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OutputOtp<'a> {
    link: Option<()>,
    label: &'a str,
    account: &'a str,
    issuer: &'a str,
    algorithm: String,
    digits: u32,
    period: u32,
    token_type: &'static str,
    counter: u64,
    source: &'static str,
}

pub fn encode(accounts: &[Account]) -> Result<Zeroizing<Vec<u8>>> {
    let updated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Invalid("system clock is before the Unix epoch"))?
        .as_millis() as u64;
    let file = OutputFile {
        schema_version: 4,
        groups: vec![],
        updated_at,
        app_origin: "otpauth-bridge",
        app_version_code: 1,
        app_version_name: env!("CARGO_PKG_VERSION"),
        services_encrypted: None,
        reference: None,
        services: accounts
            .iter()
            .enumerate()
            .map(|(index, account)| OutputService {
                name: if account.issuer().is_empty() {
                    account.name()
                } else {
                    account.issuer()
                },
                secret: account.secret(),
                updated_at,
                service_type_id: None,
                order: Order { position: index },
                badge: None,
                icon: None,
                group_id: None,
                otp: OutputOtp {
                    link: None,
                    label: account.name(),
                    account: account.name(),
                    issuer: account.issuer(),
                    algorithm: account.algorithm().to_string(),
                    digits: account.digits(),
                    period: account.period(),
                    token_type: "TOTP",
                    counter: 0,
                    source: "Manual",
                },
            })
            .collect(),
    };
    Ok(Zeroizing::new(serde_json::to_vec_pretty(&file)?))
}
