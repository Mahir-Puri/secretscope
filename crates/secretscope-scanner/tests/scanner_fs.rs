//! Integration tests for working-tree scanning.

use secretscope_scanner::{scan, CredentialKind, Origin, ScanOptions};
use std::fs;
use std::path::PathBuf;

fn tmpdir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!("secretscope-fs-{tag}-{nanos}"));
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn finds_aws_key_in_working_tree() {
    let dir = tmpdir("aws");
    fs::create_dir_all(dir.join("config")).unwrap();
    fs::write(
        dir.join("config/dev.env"),
        "PORT=8080\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();

    let opts = ScanOptions::new(&dir);
    let findings = scan(&opts).unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind, CredentialKind::AwsAccessKeyId);
    assert_eq!(findings[0].line, 2);
    assert_eq!(findings[0].origin, Origin::WorkingTree);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn respects_excluded_paths() {
    let dir = tmpdir("exclude");
    fs::create_dir_all(dir.join("vendored")).unwrap();
    fs::write(
        dir.join("vendored/leak.env"),
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();

    let mut opts = ScanOptions::new(&dir);
    opts.excludes = vec!["vendored".to_string()];
    let findings = scan(&opts).unwrap();

    assert!(findings.is_empty());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn skips_binary_files() {
    let dir = tmpdir("binary");
    // A NUL byte marks this as binary even though it contains a key pattern.
    fs::write(dir.join("blob.bin"), b"\x00\x01AKIAIOSFODNN7EXAMPLE\x00").unwrap();

    let findings = scan(&ScanOptions::new(&dir)).unwrap();
    assert!(findings.is_empty());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn parallel_and_sequential_agree() {
    let dir = tmpdir("parity");
    for i in 0..20 {
        fs::write(
            dir.join(format!("f{i}.env")),
            format!("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPL{i:01}\n"),
        )
        .unwrap();
    }

    let mut seq = ScanOptions::new(&dir);
    seq.parallel = false;
    let mut par = ScanOptions::new(&dir);
    par.parallel = true;

    let a = scan(&seq).unwrap();
    let b = scan(&par).unwrap();
    assert_eq!(a.len(), b.len());
    assert_eq!(a, b);
    fs::remove_dir_all(&dir).ok();
}
