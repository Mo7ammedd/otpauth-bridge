use otpauth_bridge::{
    Error, bundle,
    formats::{self, InputFormat, OutputFormat},
};

#[test]
fn authenticated_bundles_preserve_accounts_and_reject_tampering() {
    let accounts = formats::import(
        include_bytes!("fixtures/accounts.txt"),
        InputFormat::Auto,
        None,
    )
    .unwrap();
    let password = "this is a public test password";
    let sealed = formats::export(&accounts, OutputFormat::Bundle, Some(password)).unwrap();
    assert_eq!(formats::detect(&sealed).unwrap(), InputFormat::Bundle);
    assert!(
        !sealed
            .windows(b"alice@example.com".len())
            .any(|window| window == b"alice@example.com")
    );
    assert!(
        !sealed
            .windows(b"JBSWY3DPEHPK3PXP".len())
            .any(|window| window == b"JBSWY3DPEHPK3PXP")
    );
    assert_eq!(
        formats::import(&sealed, InputFormat::Auto, Some(password)).unwrap(),
        accounts
    );
    assert!(matches!(
        bundle::open(&sealed, "a different password"),
        Err(Error::Decryption)
    ));
    let mut tampered = sealed.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(matches!(
        bundle::open(&tampered, password),
        Err(Error::Decryption)
    ));
    let mut modified_header = sealed.to_vec();
    modified_header[25] ^= 1;
    assert!(matches!(
        bundle::open(&modified_header, password),
        Err(Error::Decryption)
    ));
    let second = bundle::seal(&accounts, password).unwrap();
    assert_ne!(
        &sealed[..48],
        &second[..48],
        "salt and nonce must be freshly randomized"
    );
}

#[test]
fn bundle_rejects_weak_passwords_missing_passwords_and_invalid_headers() {
    let accounts = formats::import(
        include_bytes!("fixtures/accounts.txt"),
        InputFormat::Auto,
        None,
    )
    .unwrap();
    assert!(bundle::seal(&accounts, "short").is_err());
    assert!(formats::export(&accounts, OutputFormat::Bundle, None).is_err());
    assert!(bundle::open(b"OTPBRDG\x01short", "anything").is_err());
    let mut unknown = vec![0; 100];
    unknown[..8].copy_from_slice(b"OTPBRDG\x02");
    assert!(bundle::open(&unknown, "anything").is_err());
}
