//! HTTP-layer integration tests over the real router (offline: StubSandbox +
//! no chain calls). Covers seal determinism, upload gating (intent 403, rate
//! limit 429, storage cap 503), and verify's typed 501 + divergence 409.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::Engine as _;
use ed25519_dalek::Signer;
use scb_runner::config::Config;
use scb_runner::routes;
use scb_runner::state::AppState;
use serde_json::{json, Value};
use sha2::Digest;
use std::sync::Arc;

const MASTER_HEX: &str = "4242424242424242424242424242424242424242424242424242424242424242";
// X25519 test scalar (any 32 bytes; public half derived from it).
const ENC_SECRET_HEX: &str = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0";

fn make_app(work_dir: &std::path::Path, overrides: &[(&str, String)]) -> (Router, Arc<AppState>) {
    make_app_with_sandbox(work_dir, overrides, None)
}

fn make_app_with_sandbox(
    work_dir: &std::path::Path,
    overrides: &[(&str, String)],
    sandbox: Option<Arc<dyn scb_runner::sandbox::SandboxExecutor + Send + Sync>>,
) -> (Router, Arc<AppState>) {
    make_app_with_artifacts(work_dir, overrides, sandbox, None)
}

fn make_app_with_artifacts(
    work_dir: &std::path::Path,
    overrides: &[(&str, String)],
    sandbox: Option<Arc<dyn scb_runner::sandbox::SandboxExecutor + Send + Sync>>,
    artifacts: Option<Arc<dyn scb_runner::artifacts::ArtifactSource>>,
) -> (Router, Arc<AppState>) {
    let envmap: std::collections::HashMap<String, String> = overrides
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect();
    let get = |k: &str| -> Option<String> { envmap.get(k).cloned() };
    let mut cfg = Config::build(scb_runner::config::BuildOpts {
        network: get("SCB_NETWORK").or_else(|| Some("scb-loopback".into())),
        port: get("PORT"),
        master_hex: Some(MASTER_HEX.into()),
        enc_secret_hex: Some(ENC_SECRET_HEX.into()),
        work_dir: Some(work_dir.display().to_string()),
        storage_cap: get("SCB_STORAGE_CAP_BYTES"),
        rate_max: get("SCB_RATE_LIMIT_MAX"),
        rate_window: get("SCB_RATE_LIMIT_WINDOW_SECS"),
        submission_store: None,
    })
    .expect("config");
    if let Some(sandbox) = sandbox {
        cfg.sandbox = sandbox;
    }
    cfg.artifact_source = artifacts;
    let state = Arc::new(AppState::new(cfg));
    (routes::router(state.clone()), state)
}

const PEER: &str = "127.0.0.1:40000";

async fn send(app: &mut Router, req: Request<Body>) -> (StatusCode, Value) {
    // Attach ConnectInfo the way into_make_service_with_connect_info would.
    let mut req = req;
    use axum::extract::ConnectInfo;
    req.extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from_str(PEER).unwrap()));
    use tower::util::ServiceExt;
    let res = app.clone().oneshot(req).await.expect("oneshot");
    let status = res.status();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    let v = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body)
            .unwrap_or_else(|_| json!({ "_unparsed_body": String::from_utf8_lossy(&body) }))
    };
    (status, v)
}

use std::str::FromStr;

async fn post_json(app: &mut Router, uri: &str, payload: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap();
    send(app, req).await
}

// ---- fixtures --------------------------------------------------------------

const BOUNTY_PDA_B58: &str = "H6mYd6dBAMsSNcMzu32rCrUzDzT4Q8zZ3vJqtdpjKbAt";
const ENV_HASH_HEX: &str = "0202020202020202020202020202020202020202020202020202020202020202";
const FLAG_COMMITMENT_HEX: &str =
    "9c59cbca2c8d351a8cfb7ca207148ce36495205a78b2b13e510ea94956b6251c";

/// Solver keypair + sealed upload body consistent with the enclave secret.
struct UploadFixture {
    body: Value,
}

fn upload_fixture(bounty: &str) -> UploadFixture {
    upload_fixture_with_plaintext(bounty, b"import pwn\npwn.remote(('target',1337))\n")
}

fn upload_fixture_with_plaintext(bounty: &str, plaintext: &[u8]) -> UploadFixture {
    use crypto_box::PublicKey;
    let solver = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng {});
    let enc_secret_bytes: [u8; 32] = hex::decode(ENC_SECRET_HEX).unwrap().try_into().unwrap();
    // NOTE: derive the public half from the secret — PublicKey::from(raw)
    // would interpret the bytes differently than the scalar does.
    let enc_pk = crypto_box::SecretKey::from(enc_secret_bytes).public_key();

    let sealed = PublicKey::seal(&enc_pk, &mut rand::rngs::OsRng {}, plaintext).unwrap();

    let mut h = sha2::Sha256::new();
    h.update(plaintext);
    let phash: [u8; 32] = h.finalize().into();

    let pda_bytes: [u8; 32] = bs58::decode(bounty)
        .into_vec()
        .expect("fixture bounty must be valid b58")
        .try_into()
        .expect("32 bytes");
    let intent_msg: Vec<u8> = [b"SCB_SUBMIT_V1".as_slice(), &pda_bytes, phash.as_slice()].concat();
    let sig = solver.sign(&intent_msg);
    let solver_pub_b58 = bs58::encode(solver.verifying_key().as_bytes()).into_string();

    UploadFixture {
        body: json!({
            "bounty_pda": bounty,
            "claimed_chain_view": {
                "env_blob_sha256": ENV_HASH_HEX,
                "buyer_enc_pk": "0909090909090909090909090909090909090909090909090909090909090909",
                "flag_commitment": FLAG_COMMITMENT_HEX,
                "exploit_sha256": hex::encode(phash),
            },
            "solver_pubkey": solver_pub_b58,
            "submit_intent_sig": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            "exploit_sealed_box": base64::engine::general_purpose::STANDARD.encode(sealed),
        }),
    }
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn healthz_ok() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (mut app, _s) = make_app(tmp.path(), &[]);
    let req = Request::builder()
        .uri("/internal/healthz")
        .body(Body::empty())
        .unwrap();
    let (status, v) = send(&mut app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["ok"], json!(true));
}

#[tokio::test]
async fn seal_bounty_is_deterministic_and_matches_lib() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (mut app, state) = make_app(tmp.path(), &[]);

    for _ in 0..2 {
        let (status, v) = post_json(
            &mut app,
            "/internal/seal_bounty",
            json!({ "bounty_pda": BOUNTY_PDA_B58 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["flag_commitment"], json!(FLAG_COMMITMENT_HEX));
    }
    assert_eq!(state.config().rate_limit_max, 5);
}

#[tokio::test]
async fn upload_happy_path_returns_receipt() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (mut app, _s) = make_app(tmp.path(), &[]);
    let fx = upload_fixture(BOUNTY_PDA_B58);
    let (status, v) = post_json(&mut app, "/internal/upload", fx.body.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert!(v["receipt"].is_string(), "{v}");
}

#[tokio::test]
async fn tampered_intent_signature_is_403_and_never_stored() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (mut app, _state) = make_app(tmp.path(), &[]);
    let fx = upload_fixture(BOUNTY_PDA_B58);
    let mut body = fx.body.clone();
    // flip a bit in the signature
    let sig_b64 = body["submit_intent_sig"].as_str().unwrap().to_string();
    let mut raw = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .unwrap();
    raw[3] ^= 0x01;
    body["submit_intent_sig"] = json!(base64::engine::general_purpose::STANDARD.encode(raw));

    let (status, v) = post_json(&mut app, "/internal/upload", body).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["error"], json!("intent_signature_invalid"));
    assert_eq!(
        stored_object_count(tmp.path()),
        0,
        "failed gate must not store an object"
    );
}

#[tokio::test]
async fn rate_limit_kicks_in_per_wallet() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (mut app, _s) = make_app(
        tmp.path(),
        &[
            ("SCB_RATE_LIMIT_MAX", "2".to_string()),
            ("SCB_RATE_LIMIT_WINDOW_SECS", "3600".to_string()),
        ],
    );
    // Three distinct, valid base58 PDAs (unique wallets already per fixture).
    const B2: &str = "5xgQaN6o7j3JgcCumKUpzLBu8sH4vXjLEyKTBWcFzMTD";
    const B3: &str = "9vJmVbT9YdLwBqPpZk3nE1RrCqAeGfUuSxToMhNzLaKd";
    let fixtures = [
        upload_fixture(BOUNTY_PDA_B58),
        upload_fixture(B2),
        upload_fixture(B3),
    ];
    for (i, fx) in fixtures.iter().take(2).enumerate() {
        let (status, v) = post_json(&mut app, "/internal/upload", fx.body.clone()).await;
        assert_eq!(status, StatusCode::CREATED, "attempt {i}: {v}");
    }
    // IP bucket is shared across wallets — the third attempt trips it.
    let (status, v) = post_json(&mut app, "/internal/upload", fixtures[2].body.clone()).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{v}");
}

#[tokio::test]
async fn storage_cap_yields_503_backpressure() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (mut app, _s) = make_app(
        tmp.path(),
        &[("SCB_STORAGE_CAP_BYTES", "10".to_string())], // tiny cap
    );
    let fx = upload_fixture(BOUNTY_PDA_B58); // plaintext > 10 bytes
    let (status, v) = post_json(&mut app, "/internal/upload", fx.body).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{v}");
    assert_eq!(v["error"], json!("storage_full"));
}

#[tokio::test]
async fn verify_without_upload_is_404() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (mut app, _s) = make_app(tmp.path(), &[]);
    let (status, v) = post_json(
        &mut app,
        "/internal/verify",
        json!({
            "bounty_pda": BOUNTY_PDA_B58,
            "solver_pubkey": upload_fixture(BOUNTY_PDA_B58).body["solver_pubkey"],
            "submission_receipt": "00".repeat(32),
            "claimed_chain_view": {
                "env_blob_sha256": ENV_HASH_HEX,
                "buyer_enc_pk": "09".repeat(32),
                "flag_commitment": FLAG_COMMITMENT_HEX,
                "exploit_sha256": hex::encode([3u8;32]),
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{v}");
}

#[tokio::test]
async fn verify_divergent_chain_view_is_409() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (mut app, _s) = make_app(tmp.path(), &[]);
    let fx = upload_fixture(BOUNTY_PDA_B58);
    let (_, uploaded) = post_json(&mut app, "/internal/upload", fx.body.clone()).await;

    let mut claimed = fx.body["claimed_chain_view"].clone();
    claimed["env_blob_sha256"] = json!(hex::encode([7u8; 32])); // swapped env!
    let (status, v) = post_json(
        &mut app,
        "/internal/verify",
        json!({
            "bounty_pda": BOUNTY_PDA_B58,
            "solver_pubkey": fx.body["solver_pubkey"],
            "submission_receipt": uploaded["receipt"],
            "claimed_chain_view": claimed,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["error"], json!("chain_view_divergence"));
}

#[tokio::test]
async fn verify_with_stub_sandbox_is_typed_501() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (mut app, _s) = make_app(tmp.path(), &[]);
    let fx = upload_fixture(BOUNTY_PDA_B58);
    let (_, uploaded) = post_json(&mut app, "/internal/upload", fx.body.clone()).await;

    let (status, v) = post_json(
        &mut app,
        "/internal/verify",
        json!({
            "bounty_pda": BOUNTY_PDA_B58,
            "solver_pubkey": fx.body["solver_pubkey"],
            "submission_receipt": uploaded["receipt"],
            "claimed_chain_view": fx.body["claimed_chain_view"].clone(),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{v}");
    assert_eq!(v["error"], json!("not_implemented"));
}

fn verify_fixture(fx: &UploadFixture, receipt: &str) -> Value {
    json!({
        "bounty_pda": fx.body["bounty_pda"],
        "solver_pubkey": fx.body["solver_pubkey"],
        "submission_receipt": receipt,
        "claimed_chain_view": fx.body["claimed_chain_view"],
    })
}

struct TestArtifacts {
    manifest: Vec<u8>,
    environment: Vec<u8>,
    corrupt: bool,
}

#[async_trait::async_trait]
impl scb_runner::artifacts::ArtifactSource for TestArtifacts {
    async fn chunk(
        &self,
        kind: scb_runner::artifacts::Kind,
        _: &str,
        offset: u64,
    ) -> Result<scb_runner::artifacts::Chunk, scb_runner::submission_store::StoreError> {
        assert_eq!(offset, 0);
        let mut bytes = match kind {
            scb_runner::artifacts::Kind::Manifest => self.manifest.clone(),
            scb_runner::artifacts::Kind::Environment => self.environment.clone(),
        };
        if self.corrupt {
            bytes[0] ^= 1;
        }
        Ok(scb_runner::artifacts::Chunk {
            offset,
            total_bytes: bytes.len() as u64,
            bytes,
        })
    }
}

struct AssertArtifactSandbox;
#[async_trait::async_trait]
impl scb_runner::sandbox::SandboxExecutor for AssertArtifactSandbox {
    async fn run_exploit(
        &self,
        p: &scb_runner::sandbox::RunParams<'_>,
    ) -> Result<scb_runner::sandbox::ExecOutcome, scb_runner::sandbox::SandboxError> {
        assert_eq!(
            std::fs::read(p.env_blob_path.unwrap()).unwrap(),
            b"synthetic environment"
        );
        assert_eq!(p.timeout_secs, 7);
        assert_eq!(p.memory_mb, 64);
        assert_eq!(p.target_port, 4444);
        assert_eq!(p.target_entrypoint, ["/app/target", "space in argument"]);
        assert!(p.target_image.is_none());
        Ok(scb_runner::sandbox::ExecOutcome {
            output: "no flag".into(),
            timed_out: false,
        })
    }
}

#[tokio::test]
async fn artifact_path_checks_both_hashes_and_uses_manifest_execution_limits() {
    use scb_runner::submission_store::receipt_for;
    for corrupt in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let env = b"synthetic environment".to_vec();
        let env_hash = receipt_for(&env);
        let manifest = serde_json::to_vec(&json!({
            "format_version":2, "name":"test", "image_tarball":{"url":"ignored", "sha256":env_hash},
            "target":{"kind":"tcp_service","host":"target","port":4444},
            "limits":{"timeout_seconds":7,"memory_mb":64,"cpus":1},
            "determinism":{"aslr":"off","seed":0}, "flag_placeholder":"{{FLAG}}",
            "entrypoint":["/app/target","space in argument"]
        }))
        .unwrap();
        let manifest_hash = receipt_for(&manifest);
        let source = Arc::new(TestArtifacts {
            manifest,
            environment: env,
            corrupt,
        });
        let (mut app, _) = make_app_with_artifacts(
            temp.path(),
            &[],
            Some(Arc::new(AssertArtifactSandbox)),
            Some(source),
        );
        let mut fx = upload_fixture(BOUNTY_PDA_B58);
        fx.body["claimed_chain_view"]["env_blob_sha256"] = json!(env_hash);
        let (status, uploaded) = post_json(&mut app, "/internal/upload", fx.body.clone()).await;
        assert_eq!(status, StatusCode::CREATED);
        let mut verify = verify_fixture(&fx, uploaded["receipt"].as_str().unwrap());
        // Missing manifest hash must not fall back to a parent-selected image.
        let (status, _) = post_json(&mut app, "/internal/verify", verify.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        verify["manifest_sha256"] = json!(manifest_hash);
        for (key, value) in [
            ("env_blob_path", json!("/tmp/other")),
            ("target_image", json!("other")),
            ("target_entrypoint", json!(["other"])),
            ("target_port", json!(1234)),
        ] {
            let mut overridden = verify.clone();
            overridden[key] = value;
            let (status, _) = post_json(&mut app, "/internal/verify", overridden).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{key}");
        }
        let (status, result) = post_json(&mut app, "/internal/verify", verify).await;
        assert_eq!(
            status,
            if corrupt {
                StatusCode::CONFLICT
            } else {
                StatusCode::OK
            },
            "{result}"
        );
        if !corrupt {
            assert_eq!(result["outcome"], false);
        }
        // Only the durable encrypted submission directory remains.
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    }
}

fn stored_object_count(work_dir: &std::path::Path) -> usize {
    std::fs::read_dir(work_dir.join("submissions"))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
                .count()
        })
        .unwrap_or(0)
}

#[tokio::test]
async fn hunters_uploading_to_same_bounty_do_not_displace_each_other() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (mut app, _) = make_app(tmp.path(), &[]);
    let first = upload_fixture_with_plaintext(BOUNTY_PDA_B58, b"print('first')");
    let second = upload_fixture_with_plaintext(BOUNTY_PDA_B58, b"print('second')");
    let mut receipts = Vec::new();
    for fx in [&first, &second] {
        let (status, body) = post_json(&mut app, "/internal/upload", fx.body.clone()).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        receipts.push(body["receipt"].as_str().unwrap().to_string());
    }
    // Both requests must reach the sandbox for their own matching submission.
    for (fx, receipt) in [(&first, &receipts[0]), (&second, &receipts[1])] {
        let (status, body) =
            post_json(&mut app, "/internal/verify", verify_fixture(fx, receipt)).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{body}");
    }
    let mut wrong_solver = verify_fixture(&first, &receipts[0]);
    wrong_solver["solver_pubkey"] = second.body["solver_pubkey"].clone();
    let (status, _) = post_json(&mut app, "/internal/verify", wrong_solver).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn claimed_hash_must_match_authenticated_plaintext() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (mut app, _state) = make_app(tmp.path(), &[]);
    let mut fx = upload_fixture(BOUNTY_PDA_B58);
    fx.body["claimed_chain_view"]["exploit_sha256"] = json!("03".repeat(32));
    let (status, _) = post_json(&mut app, "/internal/upload", fx.body).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(stored_object_count(tmp.path()), 0);
}

#[tokio::test]
async fn repeated_upload_is_idempotent_at_storage_cap() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (mut app, _state) = make_app(tmp.path(), &[("SCB_STORAGE_CAP_BYTES", "4096".to_string())]);
    let fx = upload_fixture_with_plaintext(BOUNTY_PDA_B58, b"print('retry')");
    let (status, first) = post_json(&mut app, "/internal/upload", fx.body.clone()).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, second) = post_json(&mut app, "/internal/upload", fx.body).await;
    assert_eq!(status, StatusCode::CREATED, "{second}");
    assert_eq!(first["receipt"], second["receipt"]);
    assert_eq!(stored_object_count(tmp.path()), 1);
}

#[tokio::test]
async fn encrypted_submission_survives_runner_restart() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (mut first_app, _) = make_app(tmp.path(), &[]);
    let fx = upload_fixture(BOUNTY_PDA_B58);
    let (status, uploaded) = post_json(&mut first_app, "/internal/upload", fx.body.clone()).await;
    assert_eq!(status, StatusCode::CREATED);
    let receipt = uploaded["receipt"].as_str().unwrap();

    // A new AppState models process restart while retaining the durable store.
    let (mut restarted_app, _) = make_app(tmp.path(), &[]);
    let (status, body) = post_json(
        &mut restarted_app,
        "/internal/verify",
        verify_fixture(&fx, receipt),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{body}");
}

#[tokio::test]
async fn modified_encrypted_submission_is_rejected_by_receipt_hash() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (mut app, _) = make_app(tmp.path(), &[]);
    let fx = upload_fixture(BOUNTY_PDA_B58);
    let (status, uploaded) = post_json(&mut app, "/internal/upload", fx.body.clone()).await;
    assert_eq!(status, StatusCode::CREATED);
    let receipt = uploaded["receipt"].as_str().unwrap();
    let object = std::fs::read_dir(tmp.path().join("submissions"))
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
        .expect("stored object")
        .path();
    let mut bytes = std::fs::read(&object).unwrap();
    let last = bytes.len() - 2;
    bytes[last] ^= 1;
    std::fs::write(object, bytes).unwrap();

    let (status, body) =
        post_json(&mut app, "/internal/verify", verify_fixture(&fx, receipt)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

struct BlockingSandbox {
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl scb_runner::sandbox::SandboxExecutor for BlockingSandbox {
    async fn run_exploit(
        &self,
        _: &scb_runner::sandbox::RunParams<'_>,
    ) -> Result<scb_runner::sandbox::ExecOutcome, scb_runner::sandbox::SandboxError> {
        self.started.notify_one();
        self.release.notified().await;
        Err(scb_runner::sandbox::SandboxError::Unsupported(
            "test completed",
        ))
    }
}

#[tokio::test]
async fn slow_verification_backpressures_second_job_but_health_remains_available() {
    let tmp = tempfile::TempDir::new().unwrap();
    let sandbox = Arc::new(BlockingSandbox {
        started: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let (mut app, _) = make_app_with_sandbox(tmp.path(), &[], Some(sandbox.clone()));
    let fx = upload_fixture(BOUNTY_PDA_B58);
    let (status, uploaded) = post_json(&mut app, "/internal/upload", fx.body.clone()).await;
    assert_eq!(status, StatusCode::CREATED);
    let receipt = uploaded["receipt"].as_str().unwrap().to_string();
    let mut first_app = app.clone();
    let first_request = verify_fixture(&fx, &receipt);
    let first =
        tokio::spawn(
            async move { post_json(&mut first_app, "/internal/verify", first_request).await },
        );
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        sandbox.started.notified(),
    )
    .await
    .expect("sandbox started");
    let (status, body) =
        post_json(&mut app, "/internal/verify", verify_fixture(&fx, &receipt)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"], "verifier_busy");
    let health = Request::builder()
        .uri("/internal/healthz")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&mut app, health).await.0, StatusCode::OK);
    sandbox.release.notify_one();
    assert_eq!(first.await.unwrap().0, StatusCode::NOT_IMPLEMENTED);
    // An error must release admission so the next job can run.
    sandbox.release.notify_one();
    let (status, _) = post_json(&mut app, "/internal/verify", verify_fixture(&fx, &receipt)).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
}
