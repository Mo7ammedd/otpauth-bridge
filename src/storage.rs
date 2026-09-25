use std::{
    fs::{self, File},
    io::{Read, Write},
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

pub fn ensure_new(path: &Path) -> Result<()> {
    if path.as_os_str() == "-" {
        bail!("choose an output path; secret-bearing output is never written to stdout");
    }
    match fs::symlink_metadata(path) {
        Ok(_) => bail!(
            "output already exists; choose a new path: {}",
            path.display()
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => {
            Err(err).with_context(|| format!("cannot inspect output path {}", path.display()))
        }
    }
}

/// Write beside the destination, then persist without replacing an existing file.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure_new(path)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".otpauth-bridge-")
        .tempfile_in(parent)
        .with_context(|| format!("cannot create output in {}", parent.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|err| err.error)
        .with_context(|| {
            format!(
                "cannot save {}; existing files are never replaced",
                path.display()
            )
        })?;
    Ok(())
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
