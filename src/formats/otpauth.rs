use std::collections::HashMap;

use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use url::Url;
use zeroize::Zeroizing;

use crate::{Account, Algorithm, Error, Result, Secret};

fn decode_component(value: &str, form_encoded: bool) -> Result<Zeroizing<String>> {
    let bytes = value.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'%'
            && (bytes.get(index + 1).is_none_or(|c| !c.is_ascii_hexdigit())
                || bytes.get(index + 2).is_none_or(|c| !c.is_ascii_hexdigit()))
        {
            return Err(Error::Invalid("URI contains an invalid percent escape"));
        }
    }
    let value = Zeroizing::new(if form_encoded {
        value.replace('+', " ")
    } else {
        value.to_owned()
    });
    Ok(Zeroizing::new(
        percent_decode_str(&value)
            .decode_utf8()
            .map_err(|_| Error::Invalid("URI field is not valid UTF-8"))?
            .into_owned(),
    ))
}

pub fn decode(uri: &str) -> Result<Account> {
    if uri
        .chars()
        .any(|c| c.is_ascii_whitespace() || c.is_control())
    {
        return Err(Error::Invalid(
            "URI contains unescaped whitespace or control characters",
        ));
    }
    let url = Url::parse(uri).map_err(|_| Error::Invalid("invalid otpauth URI"))?;
    if url.scheme() != "otpauth" || url.host_str() != Some("totp") {
        return Err(Error::Invalid(
            "expected an otpauth://totp/ URI; HOTP and proprietary token types are not supported",
        ));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Invalid(
            "unexpected URI credentials, port or fragment",
        ));
    }
    let label = decode_component(url.path().strip_prefix('/').unwrap_or(url.path()), false)?;
    let raw_path = uri
        .split(['?', '#'])
        .next()
        .unwrap_or(uri)
        .split_once("://")
        .and_then(|(_, authority_and_path)| authority_and_path.split_once('/'))
        .map(|(_, path)| path)
        .unwrap_or("");
    if decode_component(raw_path, false)?.as_str() != label.as_str() {
        return Err(Error::Invalid(
            "URI path normalization would change the account label",
        ));
    }
    let (label_issuer, name) = match label.split_once(':') {
        Some((issuer, name)) => (Some(issuer), name),
        None => (None, label.as_str()),
    };
    let mut fields = HashMap::new();
    for pair in url
        .query()
        .unwrap_or("")
        .split('&')
        .filter(|part| !part.is_empty())
    {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = decode_component(key, true)?;
        let value = decode_component(value, true)?;
        if !matches!(
            key.as_str(),
            "secret" | "issuer" | "algorithm" | "digits" | "period"
        ) {
            return Err(Error::Invalid(
                "unsupported otpauth parameter; accepted fields are secret, issuer, algorithm, digits and period",
            ));
        }
        if fields.insert(key.to_string(), value).is_some() {
            return Err(Error::Invalid("duplicate otpauth parameter"));
        }
    }
    let get = |key: &str| fields.get(key).map(|v| v.as_str());
    let issuer = get("issuer").or(label_issuer).unwrap_or("");
    if label_issuer.is_some_and(|prefix| prefix != issuer) {
        return Err(Error::Invalid(
            "issuer in URI label conflicts with issuer parameter",
        ));
    }
    let secret =
        Secret::from_base32(get("secret").ok_or(Error::Invalid("URI is missing its secret"))?)?;
    let algorithm = get("algorithm")
        .map(str::parse)
        .transpose()?
        .unwrap_or(Algorithm::Sha1);
    let digits = get("digits")
        .unwrap_or("6")
        .parse()
        .map_err(|_| Error::Invalid("invalid digit count"))?;
    let period = get("period")
        .unwrap_or("30")
        .parse()
        .map_err(|_| Error::Invalid("invalid TOTP period"))?;
    Account::new(
        name.into(),
        issuer.into(),
        secret,
        algorithm,
        digits,
        period,
    )
}

pub fn encode(account: &Account) -> Result<Zeroizing<String>> {
    if account.name().contains(':') || account.issuer().contains(':') {
        return Err(Error::Invalid(
            "otpauth labels cannot preserve a colon inside an account name or issuer; use Aegis, 2FAS or a bundle",
        ));
    }
    if account.issuer().is_empty() && matches!(account.name(), "." | "..") {
        return Err(Error::Invalid(
            "otpauth cannot preserve a dot-only label without an issuer; use Aegis, 2FAS or a bundle",
        ));
    }
    let name = utf8_percent_encode(account.name(), NON_ALPHANUMERIC);
    let label = if account.issuer().is_empty() {
        name.to_string()
    } else {
        format!(
            "{}:{name}",
            utf8_percent_encode(account.issuer(), NON_ALPHANUMERIC)
        )
    };
    let mut uri = Zeroizing::new(format!(
        "otpauth://totp/{label}?secret={}",
        account.secret().to_base32().as_str()
    ));
    if !account.issuer().is_empty() {
        uri.push_str("&issuer=");
        uri.push_str(&utf8_percent_encode(account.issuer(), NON_ALPHANUMERIC).to_string());
    }
    uri.push_str(&format!(
        "&algorithm={}&digits={}&period={}",
        account.algorithm(),
        account.digits(),
        account.period()
    ));
    Ok(uri)
}
