use otpauth_bridge::{
    Account, Algorithm, Error, Secret,
    formats::{self, Importer, InputFormat, OutputFormat},
};

const URIS: &[u8] = include_bytes!("fixtures/accounts.txt");

fn accounts() -> Vec<Account> {
    formats::import(URIS, InputFormat::Auto, None).unwrap()
}

#[test]
fn official_format_fixtures_produce_the_same_accounts() {
    let expected = accounts();
    for input in [
        include_bytes!("fixtures/aegis.json").as_slice(),
        include_bytes!("fixtures/twofas.json").as_slice(),
    ] {
        assert_eq!(
            formats::import(input, InputFormat::Auto, None).unwrap(),
            expected
        );
    }
}

#[test]
fn preserves_all_parameters_through_plaintext_formats() {
    let expected = accounts();
    for format in [
        OutputFormat::Otpauth,
        OutputFormat::Aegis,
        OutputFormat::Twofas,
    ] {
        let output = formats::export(&expected, format, None).unwrap();
        assert_eq!(
            formats::import(&output, InputFormat::Auto, None).unwrap(),
            expected
        );
    }
}

#[test]
fn standard_uri_encodes_unicode_and_reserved_characters() {
    let account = Account::new(
        "علي+test@example.org / work?&".into(),
        "Example & Co".into(),
        Secret::from_base32("JBSWY3DPEHPK3PXP").unwrap(),
        Algorithm::Sha512,
        7,
        45,
    )
    .unwrap();
    let uri = formats::otpauth::encode(&account).unwrap();
    assert!(!uri.contains(' '));
    assert_eq!(formats::otpauth::decode(&uri).unwrap(), account);
}

#[test]
fn issuer_only_and_account_only_labels_round_trip() {
    for (name, issuer) in [("", "Example"), ("alice@example.org", "")] {
        let account = Account::new(
            name.into(),
            issuer.into(),
            Secret::from_base32("JBSWY3DPEHPK3PXP").unwrap(),
            Algorithm::Sha1,
            6,
            30,
        )
        .unwrap();
        let uri = formats::otpauth::encode(&account).unwrap();
        assert_eq!(formats::otpauth::decode(&uri).unwrap(), account);
    }
}

#[test]
fn rejects_ambiguous_or_nonstandard_uri_parameters() {
    let base = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP";
    for suffix in [
        "&secret=JBSWY3DPEHPK3PXP",
        "&issuer=SomeoneElse",
        "&digits=5",
        "&period=0",
        "&algorithm=MD5",
        "&counter=10",
        "&encoder=steam",
        "&t0=100",
        "#fragment",
    ] {
        assert!(
            formats::otpauth::decode(&format!("{base}{suffix}")).is_err(),
            "accepted {suffix}"
        );
    }
    assert!(formats::otpauth::decode(&base.replace("totp", "hotp")).is_err());
    assert!(formats::otpauth::decode(&base.replace("alice", "%1Balice")).is_err());
}

#[test]
fn normalization_accepts_lowercase_spacing_and_valid_padding() {
    let compact = Secret::from_base32("JBSWY3DPEHPK3PXP").unwrap();
    assert_eq!(Secret::from_base32("jbsw y3dp ehpk 3pxp").unwrap(), compact);
    assert_eq!(Secret::from_base32("MY======").unwrap().as_bytes(), b"f");
    for invalid in [
        "",
        "A",
        "MZ",
        "MY=====",
        "MY=AAAAA",
        "secret!",
        "0123456789",
    ] {
        assert!(Secret::from_base32(invalid).is_err());
    }
    let debug = format!("{compact:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("JBSWY3DPEHPK3PXP"));
}

#[test]
fn mixed_files_merge_without_silently_deduplicating() {
    let mut importer = Importer::new();
    importer.add(URIS, InputFormat::Auto, None).unwrap();
    importer.add(URIS, InputFormat::Auto, None).unwrap();
    assert_eq!(importer.finish().unwrap().len(), 4);
}

#[test]
fn non_totp_entries_and_encrypted_app_backups_fail_the_import() {
    for (bytes, field, replacement) in [
        (include_str!("fixtures/aegis.json"), "\"totp\"", "\"hotp\""),
        (
            include_str!("fixtures/twofas.json"),
            "\"TOTP\"",
            "\"STEAM\"",
        ),
    ] {
        let edited = bytes.replacen(field, replacement, 1);
        assert!(formats::import(edited.as_bytes(), InputFormat::Auto, None).is_err());
    }
    let aegis = br#"{"version":1,"header":{"slots":[],"params":{}},"db":"ciphertext"}"#;
    let twofas = br#"{"schemaVersion":4,"servicesEncrypted":"ciphertext","services":[]}"#;
    for input in [aegis.as_slice(), twofas.as_slice()] {
        assert!(
            formats::import(input, InputFormat::Auto, None)
                .unwrap_err()
                .to_string()
                .contains("encrypted")
        );
    }
}

#[test]
fn twofas_null_options_use_standard_totp_defaults() {
    let input = br#"{"schemaVersion":4,"services":[{"name":"Example","secret":"JBSWY3DPEHPK3PXP","otp":{"account":"alice","algorithm":null,"digits":null,"period":null,"tokenType":null}}]}"#;
    let actual = formats::import(input, InputFormat::Auto, None).unwrap();
    assert_eq!(actual[0].algorithm(), Algorithm::Sha1);
    assert_eq!(actual[0].digits(), 6);
    assert_eq!(actual[0].period(), 30);
    assert_eq!(actual[0].issuer(), "Example");
}

#[test]
fn errors_do_not_echo_secret_payloads() {
    let bad = b"otpauth://totp/Example:alice?secret=DO-NOT-LOG-THIS-SECRET";
    let error = formats::import(bad, InputFormat::Auto, None).unwrap_err();
    assert!(!format!("{error:?} {error}").contains("DO-NOT-LOG"));
    let bad_json = br#"{"schemaVersion":"DO-NOT-LOG-THIS-SECRET","services":[]}"#;
    assert!(
        !formats::import(bad_json, InputFormat::Auto, None)
            .unwrap_err()
            .to_string()
            .contains("DO-NOT-LOG")
    );
}

#[test]
fn unsupported_target_never_changes_totp_parameters() {
    assert!(
        formats::export(&accounts(), OutputFormat::Google, None)
            .unwrap_err()
            .to_string()
            .contains("30-second")
    );
    let account = Account::new(
        "label:with:colon".into(),
        "Example".into(),
        Secret::from_base32("JBSWY3DPEHPK3PXP").unwrap(),
        Algorithm::Sha1,
        6,
        30,
    )
    .unwrap();
    assert!(formats::otpauth::encode(&account).is_err());
}

#[test]
fn empty_and_unrecognized_inputs_fail() {
    for input in [
        b"".as_slice(),
        b"# comment only",
        b"{}",
        b"not an export",
        b"[]",
        b"\xff",
    ] {
        assert!(formats::import(input, InputFormat::Auto, None).is_err());
    }
    assert!(matches!(
        formats::import(b"", InputFormat::Otpauth, None),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn utf8_bom_is_supported() {
    let mut input = b"\xef\xbb\xbf".to_vec();
    input.extend_from_slice(URIS);
    assert_eq!(
        formats::import(&input, InputFormat::Auto, None).unwrap(),
        accounts()
    );
}

#[test]
fn twofas_export_contains_exact_fields_required_by_the_app_schema() {
    let encoded = formats::export(&accounts(), OutputFormat::Twofas, None).unwrap();
    let document: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(document["schemaVersion"], 4);
    for service in document["services"].as_array().unwrap() {
        for field in [
            "name",
            "secret",
            "updatedAt",
            "serviceTypeID",
            "otp",
            "order",
            "badge",
            "icon",
            "groupId",
        ] {
            assert!(
                service.get(field).is_some(),
                "missing required 2FAS service field {field}"
            );
        }
        assert!(service.get("serviceTypeId").is_none());
        for field in [
            "link",
            "label",
            "account",
            "issuer",
            "digits",
            "period",
            "algorithm",
            "counter",
            "tokenType",
            "source",
        ] {
            assert!(
                service["otp"].get(field).is_some(),
                "missing required 2FAS OTP field {field}"
            );
        }
        assert_eq!(service["otp"]["tokenType"], "TOTP");
    }
}

#[test]
fn malformed_unicode_and_normalizing_uri_paths_are_not_silently_changed() {
    for input in [
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&issuer=%FF",
        "otpauth://totp/alice%ZZ?secret=JBSWY3DPEHPK3PXP",
        "otpauth://totp/Example:a/../b?secret=JBSWY3DPEHPK3PXP",
        "otpauth://totp/%2E?secret=JBSWY3DPEHPK3PXP",
    ] {
        assert!(formats::otpauth::decode(input).is_err());
    }
}
