//! HTTP surface: the four /internal/* endpoints (§4.3).

use crate::error::ApiError;
use crate::flag;
use crate::intent;
use crate::redact;
use crate::sandbox::{RunParams, SandboxError};
use crate::state::{AppState, BlobRecord, ChainView};
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::Json;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::net::SocketAddr;
use std::sync::Arc;

pub const FLAG_PLACEHOLDER: &str = "{{FLAG}}";

// ---- request/response payloads --------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SealBountyRequest {
    pub bounty_pda: String,
}

#[derive(Debug, Serialize)]
pub struct SealBountyResponse {
    pub flag_commitment: String,
}

#[derive(Debug, Deserialize)]
pub struct UploadRequest {
    pub bounty_pda: String,
    pub claimed_chain_view: ChainView,
    pub solver_pubkey: String,
    pub submit_intent_sig: String,
    /// base64 sealed box over the exploit plaintext.
    pub exploit_sealed_box: String,
}

#[derive(Debug, Serialize)]
pub struct UploadResponse {
    pub receipt: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub bounty_pda: String,
    pub claimed_chain_view: ChainView,
}

/// Mirrors relayer/src/enclave-types.ts `VerifyResponse` exactly.
#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub outcome: bool,
    pub sig: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reveal_ciphertext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reveal_ciphertext_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reveal_ciphertext_sha256: Option<String>,
    pub redacted_log: String,
}

fn decode_bounty_pda(s: &str) -> Result<[u8; 32], ApiError> {
    bs58::decode(s)
        .into_vec()
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| ApiError::BadRequest("bounty_pda must be base58 for a 32-byte pubkey".into()))
}

// ---- handlers ---------------------------------------------------------------

pub async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}

pub async fn seal_bounty(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SealBountyRequest>,
) -> Result<Json<SealBountyResponse>, ApiError> {
    let pda = decode_bounty_pda(&req.bounty_pda)?;
    let f = flag::derive_flag(state.master_secret(), &pda);
    let commitment = flag::flag_commitment(&f);
    Ok(Json(SealBountyResponse {
        flag_commitment: hex::encode(commitment),
    }))
}

const MAX_SEALED_BOX_BYTES: usize = 256 * 1024;

#[allow(clippy::too_many_arguments)]
pub async fn upload(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<UploadRequest>,
) -> Result<(StatusCode, Json<UploadResponse>), ApiError> {
    if req.bounty_pda.is_empty() || req.solver_pubkey.is_empty() {
        return Err(ApiError::BadRequest("empty bounty_pda or solver_pubkey".into()));
    }

    // Rate limits BEFORE any crypto work — cheapest gate first. The client
    // IP is only available when served through the real listener; unit-test
    // requests omit it and share one bucket keyed "unit-test".
    let ip_key = peer.ip().to_string();
    if !state.rate_allow(&req.solver_pubkey, &ip_key) {
        return Err(ApiError::RateLimited(state.config().rate_limit_window_secs));
    }

    // Size caps before decode.
    if req.exploit_sealed_box.len() > MAX_SEALED_BOX_BYTES.b64_len() {
        return Err(ApiError::PayloadTooLarge(format!(
            "sealed box exceeds {MAX_SEALED_BOX_BYTES} bytes"
        )));
    }
    let sealed = base64::engine::general_purpose::STANDARD
        .decode(&req.exploit_sealed_box)
        .map_err(|_| ApiError::BadRequest("exploit_sealed_box must be base64".into()))?;
    if sealed.len() > MAX_SEALED_BOX_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "sealed box exceeds {MAX_SEALED_BOX_BYTES} bytes"
        )));
    }

    // Unseal (cheap X25519 op) so the INTENT GATE binds the PLAINTEXT hash
    // exactly as §4.3 specifies — then reject impostors before any heavy work.
    let pda = decode_bounty_pda(&req.bounty_pda)?;
    let plaintext = state
        .config()
        .enclave_enc_secret
        .unseal(&sealed)
        .map_err(|_| ApiError::BadRequest("exploit_sealed_box does not decrypt under the enclave key".into()))?;
    let plaintext_sha256: [u8; 32] = sha2::Sha256::digest(&plaintext).into();
    intent::verify_intent(
        &pda,
        &plaintext_sha256,
        &hex_or_b58_to_32(&req.solver_pubkey)?,
        &req.submit_intent_sig,
    )
    .map_err(|e| ApiError::IntentForbidden(e.to_string()))?;

    // Storage cap accounting covers both ciphertext and kept plaintext.
    if !state.storage_try_reserve(plaintext.len() as u64) {
        return Err(ApiError::StorageFull);
    }

    let record = BlobRecord {
        solver_pubkey_b58: req.solver_pubkey.clone(),
        bounty_pda_b58: req.bounty_pda.clone(),
        plaintext,
        chain_view: ChainView {
            env_blob_sha256: req.claimed_chain_view.env_blob_sha256.clone(),
            buyer_enc_pk: req.claimed_chain_view.buyer_enc_pk.clone(),
            flag_commitment: req.claimed_chain_view.flag_commitment.clone(),
            exploit_sha256: req.claimed_chain_view.exploit_sha256.clone(),
        },
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        registered: false,
    };

    let receipt_hex = hex::encode(sha2::Sha256::digest(
        [
            sealed.as_slice(),
            req.solver_pubkey.as_bytes(),
            req.bounty_pda.as_bytes(),
        ]
        .concat(),
    ));

    state.store_upload(&req.bounty_pda, receipt_hex.clone(), record);
    tracing::info!(bounty = %req.bounty_pda, receipt = %receipt_hex, "upload stored");

    Ok((StatusCode::CREATED, Json(UploadResponse { receipt: receipt_hex })))
}

trait B64LenExt {
    fn b64_len(&self) -> usize;
}
impl B64LenExt for usize {
    fn b64_len(&self) -> usize {
        self.div_ceil(3) * 4 + 4
    }
}

fn hex_or_b58_to_32(s: &str) -> Result<[u8; 32], ApiError> {
    // Accept both hex (64 chars) and base58 (~44 chars) for ergonomics; the
    // relayer sends base58. Intent verification only needs the raw bytes.
    if s.len() == 64 {
        if let Ok(v) = hex::decode(s) {
            if let Ok(a) = v.try_into() {
                return Ok(a);
            }
        }
    }
    bs58::decode(s)
        .into_vec()
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| ApiError::BadRequest("solver_pubkey is neither hex nor base58 32 bytes".into()))
}

pub async fn verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let (receipt_hex, record) = state
        .take_latest_upload_for_bounty(&req.bounty_pda)
        .ok_or_else(|| ApiError::NotFound("no pending upload for this bounty".into()))?;

    // Chain-view divergence → hard conflict; the enclave never guesses which
    // side is right (review R1 seam).
    let stored = &record.chain_view;
    let claimed = &req.claimed_chain_view;
    let differs = stored.env_blob_sha256 != claimed.env_blob_sha256
        || stored.buyer_enc_pk != claimed.buyer_enc_pk
        || stored.flag_commitment != claimed.flag_commitment
        || stored.exploit_sha256 != claimed.exploit_sha256;
    if differs {
        return Err(ApiError::Conflict(format!(
            "claimed_chain_view diverges from enclave-side values for bounty {}",
            req.bounty_pda
        )));
    }

    // Mark registered so the TTL sweeper leaves it alone while we work.
    {
        let mut rec = record.clone();
        rec.registered = true;
        state.store_upload(&req.bounty_pda, receipt_hex.clone(), rec);
    }

    // Derive flag; refuse to produce any verdict if the on-chain commitment
    // diverges from our deterministic derivation.
    let pda = decode_bounty_pda(&req.bounty_pda)?;
    let flag = flag::derive_flag(state.master_secret(), &pda);
    let derived_commitment = flag::flag_commitment(&flag);
    let claimed_commitment = hex::decode(&claimed.flag_commitment)
        .map_err(|_| ApiError::BadRequest("flag_commitment not hex".into()))?;
    if claimed_commitment != derived_commitment.as_slice() {
        return Err(ApiError::Internal(
            "flag commitment mismatch vs enclave derivation".into(),
        ));
    }

    let cv_bytes = claimed.to_bytes().map_err(ApiError::BadRequest)?;
    let solver_bytes: [u8; 32] = bs58::decode(&record.solver_pubkey_b58)
        .into_vec()
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| ApiError::BadRequest("stored solver pubkey invalid".into()))?;

    // ---- sandbox execution (typed Unsupported => HTTP 501) -----------------
    let run_params = RunParams {
        rootfs_dir: &state.config().work_dir.join(format!("rootfs-{receipt_hex}")),
        work_dir: &state.config().work_dir.join(format!("work-{receipt_hex}")),
        exploit_py: &record.plaintext,
        target_host: "127.0.0.1".to_string(),
        target_port: 1337,
        timeout_secs: 60,
        memory_mb: 512,
        cpus: 1.0,
        aslr_off: true,
        seed: 0,
    };

    match state.config().sandbox.run_exploit(&run_params).await {
        Err(SandboxError::Unsupported(w)) => {
            Err(ApiError::NotImplemented(format!("sandbox unavailable: {w}")))
        }
        Err(SandboxError::Timeout) => Ok(Json(fail_response(&state, &cv_bytes, &solver_bytes, &pda))),
        Err(e) => Err(ApiError::Internal(format!("sandbox failure: {e}"))),
        Ok(exec_outcome) => {
            let pass = exec_outcome.output.contains(flag.expose());
            let redacted_log = redact::redact(&exec_outcome.output, &flag);

            // Fail-closed paranoia sweep: if ANY encoding survived redaction,
            // emit FAIL with an empty log rather than risk a leak.
            if redact::leaks(&redacted_log, &flag) {
                tracing::error!(bounty = %req.bounty_pda, "REDACTION LEAK — failing closed");
                return Ok(Json(fail_response(&state, &cv_bytes, &solver_bytes, &pda)));
            }

            let response = if pass {
                let buyer_pk = crypto_box::PublicKey::from(cv_bytes.buyer_enc_pk);
                let ct = buyer_pk
                    .seal(&mut rand::rngs::OsRng, &record.plaintext)
                    .map_err(|e| ApiError::Internal(format!("sealed box encryption failed: {e}")))?;
                let ct_sha = sha2::Sha256::digest(&ct);
                VerifyResponse {
                    outcome: true,
                    sig: sign_verdict_b64(&state, &cv_bytes, &solver_bytes, &pda, true),
                    reveal_ciphertext: Some(base64::engine::general_purpose::STANDARD.encode(ct)),
                    reveal_ciphertext_url: None,
                    reveal_ciphertext_sha256: Some(hex::encode(ct_sha)),
                    redacted_log,
                }
            } else {
                fail_response(&state, &cv_bytes, &solver_bytes, &pda)
            };
            Ok(Json(response))
        }
    }
}

fn sign_verdict_b64(
    state: &AppState,
    cv: &crate::state::ChainViewBytes,
    solver: &[u8; 32],
    bounty_pda: &[u8; 32],
    outcome: bool,
) -> String {
    let (sig, _) = crate::verdict::sign_verdict(
        state.verdict_key(),
        &crate::verdict::VerdictFields {
            bounty_pda,
            env_blob_sha256: &cv.env_blob_sha256,
            exploit_sha256: &cv.exploit_sha256,
            solver,
            flag_commitment: &cv.flag_commitment,
            outcome,
        },
    );
    base64::engine::general_purpose::STANDARD.encode(sig)
}

fn fail_response(
    state: &AppState,
    cv: &crate::state::ChainViewBytes,
    solver: &[u8; 32],
    bounty_pda: &[u8; 32],
) -> VerifyResponse {
    VerifyResponse {
        outcome: false,
        sig: sign_verdict_b64(state, cv, solver, bounty_pda, false),
        reveal_ciphertext: None,
        reveal_ciphertext_url: None,
        reveal_ciphertext_sha256: None,
        redacted_log: String::new(),
    }
}

/// Builds the /internal/* router.
pub fn router(state: std::sync::Arc<AppState>) -> axum::Router {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/internal/healthz", get(healthz))
        .route("/internal/seal_bounty", post(seal_bounty))
        .route("/internal/upload", post(upload))
        .route("/internal/verify", post(verify))
        .with_state(state)
}

