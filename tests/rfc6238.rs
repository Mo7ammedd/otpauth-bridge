use hmac::{Hmac, Mac};
use otpauth_bridge::{
    Account, Algorithm, Secret,
    formats::{self, InputFormat, OutputFormat},
};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

// RFC 6238 Appendix B is independent of the migration implementation.
// Recompute codes after export/import to catch changes to any TOTP parameter.
fn code(account: &Account, time: u64) -> String {
    let counter = (time / u64::from(account.period())).to_be_bytes();
    macro_rules! digest {
        ($hash:ty) => {{
            let mut mac = Hmac::<$hash>::new_from_slice(account.secret().as_bytes()).unwrap();
            mac.update(&counter);
            mac.finalize().into_bytes().to_vec()
        }};
    }
    let digest = match account.algorithm() {
        Algorithm::Sha1 => digest!(Sha1),
        Algorithm::Sha256 => digest!(Sha256),
        Algorithm::Sha512 => digest!(Sha512),
    };
    let offset = (digest.last().unwrap() & 0x0f) as usize;
    let truncated =
        u32::from_be_bytes(digest[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
    format!(
        "{:0width$}",
        truncated % 10_u32.pow(account.digits()),
        width = account.digits() as usize
    )
}

#[test]
fn rfc6238_codes_survive_every_plaintext_format() {
    let cases = [
        (Algorithm::Sha1, "12345678901234567890"),
        (Algorithm::Sha256, "12345678901234567890123456789012"),
        (
            Algorithm::Sha512,
            "1234567890123456789012345678901234567890123456789012345678901234",
        ),
    ];
    let accounts: Vec<_> = cases
        .iter()
        .map(|(algorithm, secret)| {
            Account::new(
                format!("rfc-{algorithm}"),
                "RFC 6238".into(),
                Secret::from_bytes(secret.as_bytes().to_vec()).unwrap(),
                *algorithm,
                8,
                30,
            )
            .unwrap()
        })
        .collect();
    let vectors = [
        (59, ["94287082", "46119246", "90693936"]),
        (1_111_111_109, ["07081804", "68084774", "25091201"]),
        (1_111_111_111, ["14050471", "67062674", "99943326"]),
        (1_234_567_890, ["89005924", "91819424", "93441116"]),
        (2_000_000_000, ["69279037", "90698825", "38618901"]),
        (20_000_000_000, ["65353130", "77737706", "47863826"]),
    ];
    for format in [
        OutputFormat::Otpauth,
        OutputFormat::Aegis,
        OutputFormat::Twofas,
        OutputFormat::Google,
    ] {
        let exported = formats::export(&accounts, format, None).unwrap();
        let imported = formats::import(&exported, InputFormat::Auto, None).unwrap();
        assert_eq!(imported, accounts);
        for (time, expected) in vectors {
            for (index, account) in imported.iter().enumerate() {
                assert_eq!(
                    code(account, time),
                    expected[index],
                    "{format:?}, time {time}, account {index}"
                );
            }
        }
    }
}
