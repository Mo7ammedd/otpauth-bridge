use base64::{Engine, engine::general_purpose::STANDARD};
use otpauth_bridge::{
    Error,
    formats::{self, Importer, InputFormat, OutputFormat},
};

// Independently constructed protobuf wire data, using the documented field numbers.
// No production protobuf encoder is used for the decoder compatibility tests.
fn migration(
    version: u8,
    kind: u8,
    algorithm: u8,
    digits: u8,
    batch_size: u8,
    batch_index: u8,
) -> String {
    let mut entry = vec![0x0a, 20];
    entry.extend_from_slice(b"12345678901234567890");
    entry.extend_from_slice(&[0x12, 23]);
    entry.extend_from_slice(b"Example:alice@test.test");
    entry.extend_from_slice(&[0x1a, 7]);
    entry.extend_from_slice(b"Example");
    entry.extend_from_slice(&[0x20, algorithm, 0x28, digits, 0x30, kind]);
    let mut payload = vec![0x0a, entry.len() as u8];
    payload.extend(entry);
    payload.extend_from_slice(&[0x10, version, 0x18, batch_size, 0x20, batch_index, 0x28, 42]);
    let base64 = STANDARD.encode(payload);
    format!(
        "otpauth-migration://offline?data={}",
        percent_encoding::utf8_percent_encode(&base64, percent_encoding::NON_ALPHANUMERIC)
    )
}

#[test]
fn imports_independent_google_wire_fixture() {
    let input = migration(1, 2, 1, 1, 1, 0);
    let accounts = formats::import(input.as_bytes(), InputFormat::Auto, None).unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].name(), "alice@test.test");
    assert_eq!(accounts[0].issuer(), "Example");
    assert_eq!(accounts[0].secret().as_bytes(), b"12345678901234567890");
    assert_eq!(accounts[0].digits(), 6);
    assert_eq!(accounts[0].period(), 30);
}

#[test]
fn google_batches_require_every_part_once() {
    let first = migration(1, 2, 1, 1, 2, 0);
    let second = migration(1, 2, 1, 1, 2, 1);
    assert!(matches!(
        formats::import(first.as_bytes(), InputFormat::Auto, None),
        Err(Error::IncompleteBatch {
            received: 1,
            expected: 2
        })
    ));
    let mut importer = Importer::new();
    importer
        .add(second.as_bytes(), InputFormat::Auto, None)
        .unwrap();
    importer
        .add(first.as_bytes(), InputFormat::Auto, None)
        .unwrap();
    assert_eq!(importer.finish().unwrap().len(), 2);
    let duplicate = format!("{first}\n{first}\n{second}");
    assert!(
        formats::import(duplicate.as_bytes(), InputFormat::Auto, None)
            .unwrap_err()
            .to_string()
            .contains("duplicate")
    );
}

#[test]
fn rejects_unsupported_google_fields_and_damaged_payloads() {
    for input in [
        migration(2, 2, 1, 1, 1, 0), // Future version.
        migration(1, 1, 1, 1, 1, 0), // HOTP.
        migration(1, 2, 4, 1, 1, 0), // MD5.
        migration(1, 2, 0, 1, 1, 0), // Unspecified algorithm.
        migration(1, 2, 1, 0, 1, 0), // Unspecified digits.
        migration(1, 2, 1, 1, 1, 1), // Out-of-bounds index.
        "otpauth-migration://offline?data=not-base64!".into(),
        "otpauth-migration://offline?data=AA%3D%3D&data=AA%3D%3D".into(),
    ] {
        assert!(formats::import(input.as_bytes(), InputFormat::Auto, None).is_err());
    }
}

#[test]
fn exports_and_reassembles_multiple_google_qrs() {
    let input = migration(1, 2, 2, 2, 1, 0);
    let account = formats::import(input.as_bytes(), InputFormat::Auto, None)
        .unwrap()
        .remove(0);
    let accounts = vec![account; 23];
    let export = formats::export(&accounts, OutputFormat::Google, None).unwrap();
    assert_eq!(std::str::from_utf8(&export).unwrap().lines().count(), 3);
    assert_eq!(
        formats::import(&export, InputFormat::Auto, None).unwrap(),
        accounts
    );
}

#[test]
fn mixed_standard_and_google_uris_are_supported_in_auto_mode() {
    let input = format!(
        "{}\notpauth://totp/Other:bob?secret=JBSWY3DPEHPK3PXP&issuer=Other\n",
        migration(1, 2, 1, 1, 1, 0)
    );
    assert_eq!(
        formats::import(input.as_bytes(), InputFormat::Auto, None)
            .unwrap()
            .len(),
        2
    );
    assert!(formats::import(input.as_bytes(), InputFormat::Google, None).is_err());
    assert!(formats::import(input.as_bytes(), InputFormat::Otpauth, None).is_err());
}
