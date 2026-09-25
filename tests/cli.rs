use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use otpauth_bridge::formats::{self, InputFormat};
use tempfile::TempDir;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn cli(arguments: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_otpauth-bridge"))
        .args(arguments)
        .output()
        .unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inspection_never_prints_keys() {
    let output = cli(&[
        "inspect".as_ref(),
        fixture("accounts.txt").as_os_str(),
        "--json".as_ref(),
    ]);
    assert_success(&output);
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(metadata.as_array().unwrap().len(), 2);
    assert_eq!(metadata[0]["name"], "alice@example.com");
    assert!(metadata[0].get("secret").is_none());
    for stream in [&output.stdout, &output.stderr] {
        assert!(!String::from_utf8_lossy(stream).contains("JBSWY3DPEHPK3PXP"));
    }
}

#[test]
fn converts_files_and_refuses_to_replace_existing_output() {
    let dir = TempDir::new().unwrap();
    let output = dir.path().join("aegis.json");
    let run = || {
        cli(&[
            "convert".as_ref(),
            fixture("accounts.txt").as_os_str(),
            "--to".as_ref(),
            "aegis".as_ref(),
            "--output".as_ref(),
            output.as_os_str(),
        ])
    };
    assert_success(&run());
    let first = fs::read(&output).unwrap();
    assert_eq!(
        formats::import(&first, InputFormat::Auto, None)
            .unwrap()
            .len(),
        2
    );
    let again = run();
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("already exists"));
    assert_eq!(fs::read(&output).unwrap(), first);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn a_bad_entry_prevents_all_output() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("bad.txt");
    fs::write(
        &input,
        "otpauth://hotp/Bad:alice?secret=DO-NOT-LOG-ME&counter=0",
    )
    .unwrap();
    let output = dir.path().join("result.json");
    let result = cli(&[
        "convert".as_ref(),
        fixture("accounts.txt").as_os_str(),
        input.as_os_str(),
        "--to".as_ref(),
        "aegis".as_ref(),
        "--output".as_ref(),
        output.as_os_str(),
    ]);
    assert!(!result.status.success());
    assert!(!output.exists());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("DO-NOT-LOG-ME"));
}

#[test]
fn lossful_google_export_creates_no_file() {
    let dir = TempDir::new().unwrap();
    let output = dir.path().join("google.txt");
    let result = cli(&[
        "convert".as_ref(),
        fixture("accounts.txt").as_os_str(),
        "--to".as_ref(),
        "google".as_ref(),
        "--output".as_ref(),
        output.as_os_str(),
    ]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("30-second"));
    assert!(!output.exists());
}

#[test]
fn qr_export_creates_private_decodable_files_and_metadata() {
    let dir = TempDir::new().unwrap();
    let output = dir.path().join("qr");
    let result = cli(&[
        "qr".as_ref(),
        fixture("accounts.txt").as_os_str(),
        "--output".as_ref(),
        output.as_os_str(),
    ]);
    assert_success(&result);
    assert!(result.stdout.is_empty());
    let index_bytes = fs::read(output.join("index.json")).unwrap();
    assert!(!String::from_utf8_lossy(&index_bytes).contains("JBSWY3DPEHPK3PXP"));
    let index: serde_json::Value = serde_json::from_slice(&index_bytes).unwrap();
    assert_eq!(index["files"].as_array().unwrap().len(), 2);
    assert_eq!(fs::read_dir(&output).unwrap().count(), 3);
    let inspected = cli(&[
        "inspect".as_ref(),
        output.join("0001.png").as_os_str(),
        "--json".as_ref(),
    ]);
    assert_success(&inspected);
    let metadata: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(metadata[0]["name"], "alice@example.com");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for entry in fs::read_dir(&output).unwrap() {
            assert_eq!(
                entry.unwrap().metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}

#[test]
fn encrypted_transfer_can_be_opened_with_a_password_file() {
    let dir = TempDir::new().unwrap();
    let password_file = dir.path().join("test.password");
    fs::write(&password_file, "public test password for fixture\n").unwrap();
    let bundle = dir.path().join("transfer.otpb");
    let encrypted = cli(&[
        "convert".as_ref(),
        fixture("accounts.txt").as_os_str(),
        "--to".as_ref(),
        "bundle".as_ref(),
        "--output".as_ref(),
        bundle.as_os_str(),
        "--new-password-file".as_ref(),
        password_file.as_os_str(),
    ]);
    assert_success(&encrypted);
    let inspected = cli(&[
        "inspect".as_ref(),
        bundle.as_os_str(),
        "--password-file".as_ref(),
        password_file.as_os_str(),
        "--json".as_ref(),
    ]);
    assert_success(&inspected);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&inspected.stdout)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let output = dir.path().join("twofas.2fas");
    let decrypted = cli(&[
        "convert".as_ref(),
        bundle.as_os_str(),
        "--password-file".as_ref(),
        password_file.as_os_str(),
        "--to".as_ref(),
        "twofas".as_ref(),
        "--output".as_ref(),
        output.as_os_str(),
    ]);
    assert_success(&decrypted);
    let actual = formats::import(&fs::read(output).unwrap(), InputFormat::Auto, None).unwrap();
    let expected = formats::import(
        &fs::read(fixture("accounts.txt")).unwrap(),
        InputFormat::Auto,
        None,
    )
    .unwrap();
    assert_eq!(actual, expected);
}

#[cfg(unix)]
#[test]
fn output_symlinks_are_never_followed_or_replaced() {
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("untouched.txt");
    fs::write(&target, b"keep this").unwrap();
    let output = dir.path().join("output.json");
    std::os::unix::fs::symlink(&target, &output).unwrap();
    let result = cli(&[
        "convert".as_ref(),
        fixture("accounts.txt").as_os_str(),
        "--to".as_ref(),
        "aegis".as_ref(),
        "--output".as_ref(),
        output.as_os_str(),
    ]);
    assert!(!result.status.success());
    assert_eq!(fs::read(&target).unwrap(), b"keep this");
    assert!(fs::symlink_metadata(output).unwrap().is_symlink());
}

#[test]
fn oversized_inputs_are_rejected_before_parsing() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("too-big.txt");
    fs::File::create(&input)
        .unwrap()
        .set_len(otpauth_bridge::MAX_INPUT_BYTES as u64 + 1)
        .unwrap();
    let result = cli(&["inspect".as_ref(), input.as_os_str()]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("size limit"));
}

#[test]
fn accidental_raw_uri_arguments_are_rejected_without_echoing_them() {
    let result = cli(&[
        "inspect".as_ref(),
        "otpauth://totp/Test?secret=DO-NOT-LOG-ME".as_ref(),
    ]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("file path"));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("DO-NOT-LOG-ME"));
}
