pub mod aegis;
pub mod google;
pub mod otpauth;
pub mod twofas;

use serde::{Deserialize, de::IgnoredAny};
use zeroize::Zeroizing;

use crate::{Account, Error, Result, bundle, qr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputFormat {
    #[default]
    Auto,
    Otpauth,
    Google,
    Aegis,
    Twofas,
    Bundle,
    Qr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Otpauth,
    Google,
    Aegis,
    Twofas,
    Bundle,
}

pub fn detect(bytes: &[u8]) -> Result<InputFormat> {
    if bundle::is_bundle(bytes) {
        return Ok(InputFormat::Bundle);
    }
    if qr::is_image(bytes) {
        return Ok(InputFormat::Qr);
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::Invalid("input is not a supported text file, bundle or QR image"))?;
    let text = text.trim_start_matches('\u{feff}').trim_start();
    if text.starts_with('{') {
        #[derive(Deserialize)]
        struct Shape {
            db: Option<IgnoredAny>,
            #[serde(rename = "schemaVersion")]
            schema_version: Option<IgnoredAny>,
        }
        let shape: Shape = serde_json::from_str(text)?;
        return match (shape.db.is_some(), shape.schema_version.is_some()) {
            (true, false) => Ok(InputFormat::Aegis),
            (false, true) => Ok(InputFormat::Twofas),
            _ => Err(Error::Invalid(
                "JSON is not an unambiguous Aegis or 2FAS backup",
            )),
        };
    }
    let first = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'));
    if first.is_some_and(|line| {
        line.starts_with("otpauth://") || line.starts_with("otpauth-migration://")
    }) {
        // In automatic mode, a text file may combine individual and migration URIs.
        return Ok(InputFormat::Auto);
    }
    Err(Error::Invalid(
        "unrecognized input; expected otpauth URIs, Google migration URIs, Aegis JSON, 2FAS JSON, an .otpb bundle or a PNG/JPEG QR image",
    ))
}

/// Accumulates files before checking Google batch completeness. No entries are skipped or deduplicated.
#[derive(Default)]
pub struct Importer {
    accounts: Vec<Account>,
    google_parts: Vec<google::BatchPart>,
}

impl Importer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, bytes: &[u8], format: InputFormat, password: Option<&str>) -> Result<()> {
        if bytes.len() > crate::MAX_INPUT_BYTES {
            return Err(Error::Invalid("input file exceeds the 16 MiB limit"));
        }
        let format = if format == InputFormat::Auto {
            detect(bytes)?
        } else {
            format
        };
        let mut chunk = Self::new();
        match format {
            InputFormat::Bundle => {
                chunk.accounts = bundle::open(
                    bytes,
                    password.ok_or(Error::Invalid("a password is required to open this bundle"))?,
                )?
            }
            InputFormat::Qr => {
                for text in qr::decode(bytes)? {
                    chunk.add_uri_lines(&text, InputFormat::Auto)?;
                }
            }
            _ => {
                let text = std::str::from_utf8(bytes)
                    .map_err(|_| Error::Invalid("input is not valid UTF-8"))?
                    .trim_start_matches('\u{feff}');
                match format {
                    InputFormat::Aegis => chunk.accounts = aegis::decode(text.as_bytes())?,
                    InputFormat::Twofas => chunk.accounts = twofas::decode(text.as_bytes())?,
                    _ => chunk.add_uri_lines(text, format)?,
                }
            }
        }
        if self.accounts.len() + chunk.accounts.len() > crate::MAX_ACCOUNTS {
            return Err(Error::Invalid("migration exceeds the 10000 account limit"));
        }
        self.accounts.extend(chunk.accounts);
        self.google_parts.extend(chunk.google_parts);
        Ok(())
    }

    fn add_uri_lines(&mut self, text: &str, format: InputFormat) -> Result<()> {
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let result = if line.starts_with("otpauth://") && format != InputFormat::Google {
                otpauth::decode(line).map(|account| self.accounts.push(account))
            } else if line.starts_with("otpauth-migration://") && format != InputFormat::Otpauth {
                google::decode(line).map(|(accounts, part)| {
                    self.accounts.extend(accounts);
                    self.google_parts.push(part);
                })
            } else {
                Err(Error::Invalid(
                    "expected one supported URI per line; input does not match the selected format",
                ))
            };
            result.map_err(|err| err.line(index + 1))?;
            if self.accounts.len() > crate::MAX_ACCOUNTS {
                return Err(Error::Invalid("migration exceeds the 10000 account limit"));
            }
        }
        Ok(())
    }

    pub fn finish(self) -> Result<Vec<Account>> {
        google::validate_batches(&self.google_parts)?;
        if self.accounts.is_empty() {
            return Err(Error::Invalid("input contains no TOTP accounts"));
        }
        Ok(self.accounts)
    }
}

pub fn import(bytes: &[u8], format: InputFormat, password: Option<&str>) -> Result<Vec<Account>> {
    let mut importer = Importer::new();
    importer.add(bytes, format, password)?;
    importer.finish()
}

pub fn export(
    accounts: &[Account],
    format: OutputFormat,
    password: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    if accounts.is_empty() || accounts.len() > crate::MAX_ACCOUNTS {
        return Err(Error::Invalid(
            "export must contain between 1 and 10000 accounts",
        ));
    }
    let output = match format {
        OutputFormat::Aegis => aegis::encode(accounts)?,
        OutputFormat::Twofas => twofas::encode(accounts)?,
        OutputFormat::Bundle => bundle::seal(
            accounts,
            password.ok_or(Error::Invalid("a password is required to create a bundle"))?,
        )?,
        OutputFormat::Otpauth => join_lines(
            accounts
                .iter()
                .map(otpauth::encode)
                .collect::<Result<Vec<_>>>()?,
        ),
        OutputFormat::Google => join_lines(google::encode(accounts)?),
    };
    if output.len() > crate::MAX_INPUT_BYTES {
        return Err(Error::Invalid("export exceeds the 16 MiB file limit"));
    }
    Ok(output)
}

fn join_lines(lines: Vec<Zeroizing<String>>) -> Zeroizing<Vec<u8>> {
    let mut output = Zeroizing::new(Vec::new());
    for line in lines {
        output.extend_from_slice(line.as_bytes());
        output.push(b'\n');
    }
    output
}
