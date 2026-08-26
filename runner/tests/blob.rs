//! Lane B (B2) blob fetch tests — local round-trip, oversize abort,
//! hash-mismatch abort with NO persisted file at dest.
//! HTTPS streaming is REASONED (curl delegation; same stage_then_commit path).

use scb_runner::blob_fetch::{fetch_blob, FetchError};
use sha2::Digest as _;

fn sha_hex(data: &[u8]) -> String {
    let mut d = sha2::Sha256::new();
    d.update(data);
    hex::encode(d.finalize())
}

#[tokio::test]
async fn ok_case_local_round_trip() {
    let tmp = tempfile::TempDir::new().unwrap();
    let src = tmp.path().join("input.tar.gz");
    let data = vec![0xEFu8; 2048];
    std::fs::write(&src, &data).unwrap();

    let dest = tmp.path().join("output.tar.gz");
    let (total, got) = fetch_blob(
        src.to_str().unwrap(),
        &dest,
        4096,
        Some(&sha_hex(&data)),
    )
    .await
    .unwrap();
    assert_eq!(total, 2048);
    assert_eq!(got, sha_hex(&data));
    // staged .part file must be gone after commit
    assert!(!dest.with_extension("part").exists());
    assert!(dest.exists());
}

#[tokio::test]
async fn mismatch_aborts_and_persists_nothing() {
    let tmp = tempfile::TempDir::new().unwrap();
    let src = tmp.path().join("in.bin");
    let data = b"actual-bytes";
    std::fs::write(&src, data).unwrap();

    let dest = tmp.path().join("out.bin");
    let wrong = "0".repeat(64);
    let err = fetch_blob(src.to_str().unwrap(), &dest, 4096, Some(&wrong))
        .await
        .unwrap_err();
    match err {
        FetchError::HashMismatch { expected, got } => {
            assert_eq!(expected, wrong);
            assert_eq!(got, sha_hex(data));
        }
        other => panic!("expected HashMismatch, got {other}"),
    }
    // Nothing at dest and no leftover staging file.
    assert!(!dest.exists(), "dest must not exist after mismatch abort");
    assert!(
        !dest.with_extension("part").exists(),
        "staging file must be cleaned up"
    );
}

#[tokio::test]
async fn oversize_aborts_before_persist() {
    let tmp = tempfile::TempDir::new().unwrap();
    let src = tmp.path().join("big.bin");
    std::fs::write(&src, vec![0xFF; 4096]).unwrap();

    let dest = tmp.path().join("out.bin");
    let err = fetch_blob(
        src.to_str().unwrap(),
        &dest,
        1024,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, FetchError::TooLarge { limit: 1024 }), "{err}");
    assert!(!dest.exists());
    assert!(!dest.with_extension("part").exists());
}

#[tokio::test]
async fn unsupported_scheme_rejected() {
    let tmp = tempfile::TempDir::new().unwrap();
    let err = fetch_blob(
        "gopher://old-school",
        &tmp.path().join("x"),
        1024,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        FetchError::UnsupportedScheme(ref s) if s == "gopher"
    ));
}
