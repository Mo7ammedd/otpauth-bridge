use serde::{Deserialize, Serialize, de::IgnoredAny};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{Account, Error, Result, Secret};

#[derive(Deserialize)]
struct InputFile {
    version: u32,
    header: InputHeader,
    db: InputDb,
}

#[derive(Deserialize)]
struct InputHeader {
    slots: Option<IgnoredAny>,
    params: Option<IgnoredAny>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum InputDb {
    Plain {
        version: u32,
        entries: Vec<InputEntry>,
    },
    Encrypted(String),
}

#[derive(Deserialize)]
struct InputEntry {
    #[serde(rename = "type")]
    kind: String,
    name: String,
    #[serde(default)]
    issuer: String,
    info: Info,
}

#[derive(Serialize, Deserialize)]
struct Info {
    secret: Secret,
    algo: String,
    digits: u32,
    #[serde(default = "default_period")]
    period: u32,
}

fn default_period() -> u32 {
    30
}

pub fn decode(bytes: &[u8]) -> Result<Vec<Account>> {
    let file: InputFile = serde_json::from_slice(bytes)?;
    if file.version != 1 {
        return Err(Error::Invalid(
            "unsupported Aegis file version; expected version 1",
        ));
    }
    if file.header.slots.is_some() || file.header.params.is_some() {
        return Err(Error::Invalid(
            "encrypted Aegis backups are not supported; export a plain JSON backup from Aegis first",
        ));
    }
    let (version, entries) = match file.db {
        InputDb::Plain { version, entries } => (version, entries),
        InputDb::Encrypted(data) => {
            drop(data);
            return Err(Error::Invalid(
                "encrypted Aegis backups are not supported; export a plain JSON backup from Aegis first",
            ));
        }
    };
    if !(1..=3).contains(&version) {
        return Err(Error::Invalid(
            "unsupported Aegis database version; expected version 1, 2 or 3",
        ));
    }
    entries
        .into_iter()
        .enumerate()
        .map(|(index, entry)| convert_entry(entry).map_err(|err| err.entry(index + 1)))
        .collect()
}

fn convert_entry(entry: InputEntry) -> Result<Account> {
    if entry.kind != "totp" {
        return Err(Error::Invalid("Aegis backup contains a non-TOTP entry"));
    }
    Account::new(
        entry.name,
        entry.issuer,
        entry.info.secret,
        entry.info.algo.parse()?,
        entry.info.digits,
        entry.info.period,
    )
}

#[derive(Serialize)]
struct OutputFile<'a> {
    version: u32,
    header: OutputHeader,
    db: OutputDb<'a>,
}
#[derive(Serialize)]
struct OutputHeader {
    slots: Option<()>,
    params: Option<()>,
}
#[derive(Serialize)]
struct OutputDb<'a> {
    version: u32,
    entries: Vec<OutputEntry<'a>>,
    groups: Vec<()>,
    icons_optimized: bool,
}
#[derive(Serialize)]
struct OutputEntry<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    uuid: String,
    name: &'a str,
    issuer: &'a str,
    note: &'static str,
    favorite: bool,
    icon: Option<()>,
    groups: Vec<()>,
    info: OutputInfo<'a>,
}
#[derive(Serialize)]
struct OutputInfo<'a> {
    secret: &'a Secret,
    algo: String,
    digits: u32,
    period: u32,
}

pub fn encode(accounts: &[Account]) -> Result<Zeroizing<Vec<u8>>> {
    let file = OutputFile {
        version: 1,
        header: OutputHeader {
            slots: None,
            params: None,
        },
        db: OutputDb {
            version: 3,
            groups: vec![],
            icons_optimized: true,
            entries: accounts
                .iter()
                .map(|account| OutputEntry {
                    kind: "totp",
                    uuid: Uuid::new_v4().to_string(),
                    name: account.name(),
                    issuer: account.issuer(),
                    note: "",
                    favorite: false,
                    icon: None,
                    groups: vec![],
                    info: OutputInfo {
                        secret: account.secret(),
                        algo: account.algorithm().to_string(),
                        digits: account.digits(),
                        period: account.period(),
                    },
                })
                .collect(),
        },
    };
    Ok(Zeroizing::new(serde_json::to_vec_pretty(&file)?))
}
