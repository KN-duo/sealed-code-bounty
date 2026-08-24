//! HTTP-layer integration tests over the real router (offline: StubSandbox +
//! no chain calls). Covers seal determinism, upload gating (intent 403, rate
//! limit 429, storage cap 503), and verify's typed 501 + divergence 409.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use scb_runner::config::Config;
use scb_runner::routes;
use scb_runner::state::AppState;
use ed25519_dalek::Signer;
use sha2::Digest;
use base64::Engine as _;
use serde_json::{json, Value};
use std::sync::Arc;

const MASTER_HEX: &str = "4242424242424242424242424242424242424242424242424242424242424242";
// X25519 test scalar (any 32 bytes; public half derived from it).
const ENC_SECRET_HEX: &str = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0";

fn make_app(
    work_dir: &std::path::Path,
    overrides: &[(&str, String)],
) -> (Router, Arc<AppState>) {
    let envmap: std::collections::HashMap<String, String> =
        overrides
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect();
    let get = |k: &str| -> Option<String> { envmap.get(k).cloned() };
    let cfg = Config::build(scb_runner::config::BuildOpts {
        port: get("PORT"),
        master_hex: Some(MASTER_HEX.into()),
        enc_secret_hex: Some(ENC_SECRET_HEX.into()),
        work_dir: Some(work_dir.display().to_string()),
        storage_cap: get("SCB_STORAGE_CAP_BYTES"),
        blob_ttl: get("SCB_BLOB_TTL_SECS"),
        rate_max: get("SCB_RATE_LIMIT_MAX"),
        rate_window: get("SCB_RATE_LIMIT_WINDOW_SECS"),
    })
    .expect("config");
    let state = Arc::new(AppState::new(cfg));
    (routes::router(state.clone()), state)
}

const PEER: &str = "127.0.0.1:40000";

async fn send(app: &mut Router, req: Request<Body>) -> (StatusCode, Value) {
    // Attach ConnectInfo the way into_make_service_with_connect_info would.
    let mut req = req;
    use axum::extract::ConnectInfo;
    req.extensions_mut().insert(ConnectInfo(
        std::net::SocketAddr::from_str(PEER).unwrap(),
    ));
    use tower::util::ServiceExt;
    let res = app.clone().oneshot(req).await.expect("oneshot");
    let status = res.status();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    let v = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap_or_else(|_| {
            json!({ "_unparsed_body": String::from_utf8_lossy(&body) })
        })
    };
    (status, v)
}

use std::str::FromStr;

async fn post_json(
    app: &mut Router,
    uri: &str,
    payload: Value,
) -> (StatusCode, Value) {
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
    use crypto_box::PublicKey;
    let solver = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng {});
    let enc_secret_bytes: [u8; 32] = hex::decode(ENC_SECRET_HEX).unwrap().try_into().unwrap();
    // NOTE: derive the public half from the secret — PublicKey::from(raw)
    // would interpret the bytes differently than the scalar does.
    let enc_pk = crypto_box::SecretKey::from(enc_secret_bytes).public_key();

    let plaintext = b"import pwn\npwn.remote(('target',1337))\n".to_vec();
    let sealed = PublicKey::seal(&enc_pk, &mut rand::rngs::OsRng {}, &plaintext).unwrap();

    let mut h = sha2::Sha256::new();
    h.update(&plaintext);
    let phash: [u8; 32] = h.finalize().into();

    let pda_bytes: [u8; 32] = bs58::decode(bounty)
        .into_vec()
        .expect("fixture bounty must be valid b58")
        .try_into()
        .expect("32 bytes");
    let intent_msg: Vec<u8> = [
        b"SCB_SUBMIT_V1".as_slice(),
        &pda_bytes,
        phash.as_slice(),
    ]
    .concat();
    let sig = solver.sign(&intent_msg);
    let solver_pub_b58 = bs58::encode(solver.verifying_key().as_bytes()).into_string();

    let _ = &plaintext;
    UploadFixture {
        body: json!({
            "bounty_pda": bounty,
            "claimed_chain_view": {
                "env_blob_sha256": ENV_HASH_HEX,
                "buyer_enc_pk": "0909090909090909090909090909090909090909090909090909090909090909",
                "flag_commitment": FLAG_COMMITMENT_HEX,
                "exploit_sha256": hex::encode([3u8;32]),
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
    let req = Request::builder().uri("/internal/healthz").body(Body::empty()).unwrap();
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
    let (mut app, state) = make_app(tmp.path(), &[]);
    let fx = upload_fixture(BOUNTY_PDA_B58);
    let mut body = fx.body.clone();
    // flip a bit in the signature
    let sig_b64 = body["submit_intent_sig"].as_str().unwrap().to_string();
    let mut raw = base64::engine::general_purpose::STANDARD.decode(sig_b64).unwrap();
    raw[3] ^= 0x01;
    body["submit_intent_sig"] =
        json!(base64::engine::general_purpose::STANDARD.encode(raw));

    let (status, v) = post_json(&mut app, "/internal/upload", body).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["error"], json!("intent_signature_invalid"));
    assert_eq!(
        state.storage_used(),
        0,
        "failed gate must not reserve storage"
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
    post_json(&mut app, "/internal/upload", fx.body.clone()).await;

    let mut claimed = fx.body["claimed_chain_view"].clone();
    claimed["env_blob_sha256"] = json!(hex::encode([7u8; 32])); // swapped env!
    let (status, v) = post_json(
        &mut app,
        "/internal/verify",
        json!({ "bounty_pda": BOUNTY_PDA_B58, "claimed_chain_view": claimed }),
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
    post_json(&mut app, "/internal/upload", fx.body.clone()).await;

    let (status, v) = post_json(
        &mut app,
        "/internal/verify",
        json!({
            "bounty_pda": BOUNTY_PDA_B58,
            "claimed_chain_view": fx.body["claimed_chain_view"].clone(),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{v}");
    assert_eq!(v["error"], json!("not_implemented"));
}

