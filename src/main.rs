mod storage;

use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use otpauth_bridge::{
    Account,
    formats::{self, Importer, InputFormat, OutputFormat},
};
use serde::Serialize;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "Offline TOTP migration between authenticator apps",
    long_about = "Move TOTP accounts between Google Authenticator, Aegis, 2FAS and standard QR codes. All processing stays on this machine. Existing output paths are never replaced."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Preview accounts and TOTP parameters without revealing secrets
    Inspect {
        #[command(flatten)]
        input: Inputs,
        /// Print metadata as JSON (never includes secret keys)
        #[arg(long)]
        json: bool,
    },
    /// Convert or merge exports into a new file
    Convert {
        #[command(flatten)]
        input: Inputs,
        /// Destination file format
        #[arg(long, value_enum)]
        to: Destination,
        /// New output file; parent directory must already exist
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
        /// Read the NEW bundle password from a file instead of prompting
        #[arg(long, value_name = "FILE")]
        new_password_file: Option<PathBuf>,
    },

}

#[derive(Args)]
struct Inputs {
    /// Export files or QR images; supply every part of a Google batch together
    #[arg(required = true, value_name = "INPUT")]
    paths: Vec<PathBuf>,
    /// Source format; auto detects each file separately
    #[arg(long, value_enum, default_value_t = Source::Auto)]
    from: Source,
    /// Read the input bundle password from a file instead of prompting
    #[arg(long, value_name = "FILE")]
    password_file: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Source {
    Auto,
    Otpauth,
    Google,
    Aegis,
    Twofas,
    Bundle,
    Qr,
}

impl From<Source> for InputFormat {
    fn from(value: Source) -> Self {
        match value {
            Source::Auto => Self::Auto,
            Source::Otpauth => Self::Otpauth,
            Source::Google => Self::Google,
            Source::Aegis => Self::Aegis,
            Source::Twofas => Self::Twofas,
            Source::Bundle => Self::Bundle,
            Source::Qr => Self::Qr,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Destination {
    Otpauth,
    Google,
    Aegis,
    Twofas,
    Bundle,
}

impl From<Destination> for OutputFormat {
    fn from(value: Destination) -> Self {
        match value {
            Destination::Otpauth => Self::Otpauth,
            Destination::Google => Self::Google,
            Destination::Aegis => Self::Aegis,
            Destination::Twofas => Self::Twofas,
            Destination::Bundle => Self::Bundle,
        }
    }
}

#[derive(Serialize)]
struct Metadata<'a> {
    index: usize,
    name: &'a str,
    issuer: &'a str,
    algorithm: String,
    digits: u32,
    period: u32,
}

fn metadata(accounts: &[Account]) -> Vec<Metadata<'_>> {
    accounts
        .iter()
        .enumerate()
        .map(|(index, account)| Metadata {
            index: index + 1,
            name: account.name(),
            issuer: account.issuer(),
            algorithm: account.algorithm().to_string(),
            digits: account.digits(),
            period: account.period(),
        })
        .collect()
}

fn load(input: &Inputs) -> Result<Vec<Account>> {
    let mut importer = Importer::new();
    let mut password = None;
    for path in &input.paths {
        if path.to_str().is_some_and(|value| {
            value.starts_with("otpauth://") || value.starts_with("otpauth-migration://")
        }) {
            bail!("supply a file path, not a raw URI; store URI input in a local file");
        }
        let bytes = storage::read_bounded(path, otpauth_bridge::MAX_INPUT_BYTES)?;
        let selected: InputFormat = input.from.into();
        let format = if selected == InputFormat::Auto {
            formats::detect(&bytes)
                .with_context(|| format!("cannot identify {}", path.display()))?
        } else {
            selected
        };
        if format == InputFormat::Bundle && password.is_none() {
            password = Some(match &input.password_file {
                Some(path) => storage::read_password(path)?,
                None => prompt("Input bundle password: ")?,
            });
        }
        importer
            .add(
                &bytes,
                format,
                password.as_ref().map(|value| value.as_str()),
            )
            .with_context(|| format!("cannot import {}", path.display()))?;
    }
    Ok(importer.finish()?)
}

fn prompt(message: &str) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(
        rpassword::prompt_password(message).context(
            "cannot read password from terminal; use a password file for noninteractive commands",
        )?,
    ))
}

fn new_password(path: Option<&Path>) -> Result<Zeroizing<String>> {
    match path {
        Some(path) => storage::read_password(path),
        None => {
            let password = prompt("New bundle password (at least 12 characters): ")?;
            let confirmation = prompt("Confirm new bundle password: ")?;
            if password.as_str() != confirmation.as_str() {
                bail!("passwords do not match");
            }
            Ok(password)
        }
    }
}

fn inspect(accounts: &[Account], json: bool) -> Result<()> {
    let metadata = metadata(accounts);
    let mut stdout = io::stdout().lock();
    if json {
        serde_json::to_writer_pretty(&mut stdout, &metadata)?;
        writeln!(stdout)?;
    } else {
        writeln!(
            stdout,
            "{} TOTP account(s); secret keys are hidden",
            accounts.len()
        )?;
        for account in metadata {
            // Escape formatting characters even though control characters were rejected at import.
            writeln!(
                stdout,
                "{:>3}. {} / {}  [{} · {} digits · {}s]",
                account.index,
                account.issuer.escape_debug(),
                account.name.escape_debug(),
                account.algorithm,
                account.digits,
                account.period
            )?;
        }
    }
    Ok(())
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Inspect { input, json } => inspect(&load(&input)?, json),
        Command::Convert {
            input,
            to,
            output,
            new_password_file,
        } => {
            storage::ensure_new(&output)?;
            if to != Destination::Bundle && new_password_file.is_some() {
                bail!("--new-password-file requires --to bundle");
            }
            let accounts = load(&input)?;
            let password = if to == Destination::Bundle {
                Some(new_password(new_password_file.as_deref())?)
            } else {
                None
            };
            let bytes = formats::export(
                &accounts,
                to.into(),
                password.as_ref().map(|value| value.as_str()),
            )?;
            storage::write_private(&output, &bytes)?;
            eprintln!(
                "Wrote {} account(s) to {}{}",
                accounts.len(),
                output.display(),
                if to == Destination::Bundle {
                    " (encrypted)"
                } else {
                    " (contains secret keys)"
                }
            );
            Ok(())
        }

    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
