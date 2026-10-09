use scb_runner::{manifest::Manifest, submission_store::receipt_for};
use serde_json::Value;

fn fixture() -> (Vec<u8>, String, String) {
    let fixture: Value =
        serde_json::from_str(include_str!("../../fixtures/manifest-v2.json")).unwrap();
    let bytes = fixture["canonical"].as_str().unwrap().as_bytes().to_vec();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    (
        bytes,
        fixture["sha256"].as_str().unwrap().into(),
        value["image_tarball"]["sha256"].as_str().unwrap().into(),
    )
}

#[test]
fn shared_browser_cli_rust_canonical_vector() {
    let (bytes, hash, env) = fixture();
    assert_eq!(receipt_for(&bytes), hash);
    Manifest::parse(&bytes, &env).unwrap();
    assert!(Manifest::parse(&bytes, &"0".repeat(64)).is_err());
}

#[test]
fn rejects_ambiguous_serialization_unknown_fields_and_unsafe_values() {
    let (bytes, _, env) = fixture();
    let mut spaced = bytes.clone();
    spaced.push(b'\n');
    assert!(Manifest::parse(&spaced, &env).is_err());
    let mut duplicate = String::from_utf8(bytes.clone()).unwrap();
    duplicate.insert_str(1, "\"format_version\":2,");
    assert!(Manifest::parse(duplicate.as_bytes(), &env).is_err());
    for (pointer, bad) in [
        ("/format_version", serde_json::json!(3)),
        ("/limits/timeout_seconds", serde_json::json!(61)),
        ("/limits/memory_mb", serde_json::json!(513)),
        ("/limits/cpus", serde_json::json!(2)),
        ("/entrypoint", serde_json::json!("sh -c run")),
        ("/entrypoint", serde_json::json!([])),
        ("/name", serde_json::json!("non-ascii é")),
        ("/name", serde_json::json!("line\nbreak")),
        ("/target/host", serde_json::json!("169.254.169.254")),
        ("/flag_placeholder", serde_json::json!("changed")),
    ] {
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        *value.pointer_mut(pointer).unwrap() = bad;
        assert!(
            Manifest::parse(&serde_json::to_vec(&value).unwrap(), &env).is_err(),
            "{pointer}"
        );
    }
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value["limits"]["extra"] = serde_json::json!(true);
    assert!(Manifest::parse(&serde_json::to_vec(&value).unwrap(), &env).is_err());
}
