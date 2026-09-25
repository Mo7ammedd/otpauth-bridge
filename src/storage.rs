use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

pub fn read_bounded(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    if !fs::metadata(path)
        .with_context(|| format!("cannot inspect {}", path.display()))?
        .is_file()
    {
        bail!("input must be a regular file: {}", path.display());
    }
    let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    if !file.metadata()?.is_file() {
        bail!("input must be a regular file: {}", path.display());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {}", path.display()))?;
    if bytes.len() > limit {
        bail!("input exceeds the size limit: {}", path.display());
    }
    Ok(bytes)
}

pub fn read_password(path: &Path) -> Result<Zeroizing<String>> {
    let bytes = read_bounded(path, 64 * 1024)?;
    let text = std::str::from_utf8(&bytes).context("password file must contain UTF-8 text")?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    if text.is_empty() || text.contains(['\r', '\n']) {
        bail!("password file must contain exactly one nonempty line");
    }
    Ok(Zeroizing::new(text.to_owned()))
}
