//! Versioned, authenticated transfer bundles. The v1 KDF cost is fixed, not file-controlled.

use argon2::{Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Account, Error, Result};

const MAGIC: &[u8; 8] = b"OTPBRDG\x01";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = MAGIC.len() + SALT_LEN + NONCE_LEN;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    accounts: Vec<Account>,
}

#[derive(Serialize)]
struct DocumentRef<'a> {
    version: u32,
    accounts: &'a [Account],
}

pub fn is_bundle(bytes: &[u8]) -> bool {
    bytes.starts_with(b"OTPBRDG")
}

fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(65_536, 3, 1, Some(32))
        .map_err(|_| Error::Invalid("invalid internal key derivation parameters"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|_| Error::Invalid("could not derive encryption key"))?;
    Ok(key)
}

pub fn seal(accounts: &[Account], password: &str) -> Result<Zeroizing<Vec<u8>>> {
    if password.chars().count() < 12 {
        return Err(Error::Invalid(
            "choose a bundle password of at least 12 characters",
        ));
    }
    if accounts.is_empty() || accounts.len() > crate::MAX_ACCOUNTS {
        return Err(Error::Invalid(
            "bundle must contain between 1 and 10000 accounts",
        ));
    }
    let plaintext = Zeroizing::new(serde_json::to_vec(&DocumentRef {
        version: 1,
        accounts,
    })?);
    if plaintext.len() + HEADER_LEN + 16 > crate::MAX_INPUT_BYTES {
        return Err(Error::Invalid(
            "encrypted bundle would exceed the 16 MiB file limit",
        ));
    }
    let mut header = [0; HEADER_LEN];
    header[..MAGIC.len()].copy_from_slice(MAGIC);
    OsRng
        .try_fill_bytes(&mut header[MAGIC.len()..])
        .map_err(|_| Error::Invalid("system random number generator is unavailable"))?;
    let key = derive_key(password, &header[MAGIC.len()..MAGIC.len() + SALT_LEN])?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| Error::Invalid("invalid internal encryption key length"))?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&header[MAGIC.len() + SALT_LEN..]),
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|_| Error::Invalid("could not encrypt transfer bundle"))?;
    let mut output = Zeroizing::new(Vec::with_capacity(HEADER_LEN + ciphertext.len()));
    output.extend_from_slice(&header);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn open(bytes: &[u8], password: &str) -> Result<Vec<Account>> {
    if bytes.len() > crate::MAX_INPUT_BYTES {
        return Err(Error::Invalid(
            "encrypted bundle exceeds the 16 MiB file limit",
        ));
    }
    if bytes.len() < HEADER_LEN + 16 || !bytes.starts_with(MAGIC) {
        return Err(Error::Invalid(
            "invalid or unsupported encrypted bundle header",
        ));
    }
    let (header, ciphertext) = bytes.split_at(HEADER_LEN);
    let key = derive_key(password, &header[MAGIC.len()..MAGIC.len() + SALT_LEN])?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| Error::Invalid("invalid internal encryption key length"))?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&header[MAGIC.len() + SALT_LEN..]),
                Payload {
                    msg: ciphertext,
                    aad: header,
                },
            )
            .map_err(|_| Error::Decryption)?,
    );
    let document: Document = serde_json::from_slice(&plaintext)?;
    if document.version != 1
        || document.accounts.is_empty()
        || document.accounts.len() > crate::MAX_ACCOUNTS
    {
        return Err(Error::Invalid(
            "unsupported or invalid encrypted bundle document",
        ));
    }
    Ok(document.accounts)
}
