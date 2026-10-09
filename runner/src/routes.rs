//! HTTP surface: the four /internal/* endpoints (§4.3).

use crate::error::ApiError;
use crate::flag;
use crate::intent;
use crate::sandbox::{RunParams, SandboxError};
use crate::state::{AppState, ChainView};
use crate::submission_store::{
    receipt_for, valid_receipt, StoreError, StoredSubmission, MAX_OBJECT_BYTES,
};
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::Json;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroizing;

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
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    pub bounty_pda: String,
    /// Solver from the pending on-chain submission; required to disambiguate
    /// multiple hunters who upload to the same bounty before submitting.
    pub solver_pubkey: String,
    /// Receipt extracted from the current on-chain `scb:submission:v1:` ref.
    pub submission_receipt: String,
    pub claimed_chain_view: ChainView,
    /// Hash of the exact canonical manifest bytes committed on chain.
    pub manifest_sha256: Option<String>,
    /// Local path (or https URL, typed-unsupported for now) of the packed
    /// environment tarball. The runner loads + verifies its hash.
    #[serde(default)]
    pub env_blob_path: Option<String>,
    /// Target image ref when the blob is already loaded into the daemon.
    #[serde(default)]
    pub target_image: Option<String>,
    /// Manifest entrypoint+cmd tokens (for D13 setarch wrapping).
    #[serde(default)]
    pub target_entrypoint: Vec<String>,
    /// tcp_service port from the manifest.
    pub target_port: Option<u16>,
}

fn store_error(error: StoreError) -> ApiError {
    match error {
        StoreError::InvalidReceipt | StoreError::HashMismatch => {
            ApiError::Conflict(error.to_string())
        }
        StoreError::NotFound => ApiError::NotFound(error.to_string()),
        StoreError::TooLarge => ApiError::PayloadTooLarge(error.to_string()),
        StoreError::Full => ApiError::StorageFull,
        StoreError::Unavailable => ApiError::StorageUnavailable,
    }
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
        .ok_or_else(|| {
            ApiError::BadRequest("bounty_pda must be base58 for a 32-byte pubkey".into())
        })
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
        return Err(ApiError::BadRequest(
            "empty bounty_pda or solver_pubkey".into(),
        ));
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
    let plaintext = Zeroizing::new(state.config().enclave_enc_secret.unseal(&sealed).map_err(
        |_| {
            ApiError::BadRequest("exploit_sealed_box does not decrypt under the enclave key".into())
        },
    )?);
    let plaintext_sha256: [u8; 32] = sha2::Sha256::digest(&*plaintext).into();
    intent::verify_intent(
        &pda,
        &plaintext_sha256,
        &hex_or_b58_to_32(&req.solver_pubkey)?,
        &req.submit_intent_sig,
    )
    .map_err(|e| ApiError::IntentForbidden(e.to_string()))?;

    let chain_bytes = req
        .claimed_chain_view
        .to_bytes()
        .map_err(ApiError::BadRequest)?;
    if plaintext_sha256 != chain_bytes.exploit_sha256 {
        return Err(ApiError::Conflict(
            "exploit_sha256 does not match decrypted submission".into(),
        ));
    }

    let stored = StoredSubmission {
        version: 1,
        solver_pubkey: bs58::encode(hex_or_b58_to_32(&req.solver_pubkey)?).into_string(),
        bounty_pda: bs58::encode(pda).into_string(),
        claimed_chain_view: ChainView {
            env_blob_sha256: req.claimed_chain_view.env_blob_sha256.clone(),
            buyer_enc_pk: req.claimed_chain_view.buyer_enc_pk.clone(),
            flag_commitment: req.claimed_chain_view.flag_commitment.clone(),
            exploit_sha256: req.claimed_chain_view.exploit_sha256.clone(),
        },
        submit_intent_sig: req.submit_intent_sig.clone(),
        exploit_sealed_box: base64::engine::general_purpose::STANDARD.encode(&sealed),
    };
    let object = serde_json::to_vec(&stored)
        .map_err(|_| ApiError::Internal("could not encode encrypted submission".into()))?;
    if object.len() > MAX_OBJECT_BYTES {
        return Err(ApiError::PayloadTooLarge(
            "stored encrypted submission exceeds object limit".into(),
        ));
    }
    let receipt_hex = receipt_for(&object);
    state
        .store_submission(&receipt_hex, &stored)
        .await
        .map_err(store_error)?;
    tracing::info!(bounty = %req.bounty_pda, receipt = %receipt_hex, "upload stored");

    Ok((
        StatusCode::CREATED,
        Json(UploadResponse {
            receipt: receipt_hex,
        }),
    ))
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
        .ok_or_else(|| {
            ApiError::BadRequest("solver_pubkey is neither hex nor base58 32 bytes".into())
        })
}

pub async fn verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let _verification = state.try_verification().ok_or(ApiError::VerifierBusy)?;
    if state.config().artifact_source.is_some()
        && (req.env_blob_path.is_some()
            || req.target_image.is_some()
            || !req.target_entrypoint.is_empty()
            || req.target_port.is_some())
    {
        return Err(ApiError::BadRequest(
            "target overrides are disabled with vsock artifact storage".into(),
        ));
    }
    let solver_pubkey = bs58::encode(hex_or_b58_to_32(&req.solver_pubkey)?).into_string();
    if !valid_receipt(&req.submission_receipt) {
        return Err(ApiError::BadRequest(
            "submission_receipt must be 64 lowercase hex characters".into(),
        ));
    }
    let stored = state
        .load_submission(&req.submission_receipt)
        .await
        .map_err(store_error)?;
    if stored.bounty_pda != req.bounty_pda || stored.solver_pubkey != solver_pubkey {
        return Err(ApiError::NotFound(
            "no encrypted submission matches this on-chain submission".into(),
        ));
    }

    // Chain-view divergence → hard conflict; the enclave never guesses which
    // side is right (review R1 seam).
    let uploaded = &stored.claimed_chain_view;
    let claimed = &req.claimed_chain_view;
    let differs = uploaded.env_blob_sha256 != claimed.env_blob_sha256
        || uploaded.buyer_enc_pk != claimed.buyer_enc_pk
        || uploaded.flag_commitment != claimed.flag_commitment
        || uploaded.exploit_sha256 != claimed.exploit_sha256;
    if differs {
        return Err(ApiError::Conflict(format!(
            "claimed_chain_view diverges from enclave-side values for bounty {}",
            req.bounty_pda
        )));
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
    let solver_bytes: [u8; 32] = bs58::decode(&stored.solver_pubkey)
        .into_vec()
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| ApiError::BadRequest("stored solver pubkey invalid".into()))?;

    let sealed = base64::engine::general_purpose::STANDARD
        .decode(&stored.exploit_sealed_box)
        .map_err(|_| ApiError::Conflict("stored encrypted submission is malformed".into()))?;
    if sealed.len() > MAX_SEALED_BOX_BYTES {
        return Err(ApiError::Conflict(
            "stored encrypted submission exceeds allowed size".into(),
        ));
    }
    let plaintext = Zeroizing::new(
        state
            .config()
            .enclave_enc_secret
            .unseal(&sealed)
            .map_err(|_| {
                ApiError::Conflict("stored encrypted submission cannot be opened".into())
            })?,
    );
    let plaintext_sha256: [u8; 32] = sha2::Sha256::digest(&*plaintext).into();
    if hex::encode(plaintext_sha256) != claimed.exploit_sha256.to_ascii_lowercase() {
        return Err(ApiError::Conflict(
            "stored submission hash does not match chain".into(),
        ));
    }
    intent::verify_intent(
        &pda,
        &plaintext_sha256,
        &solver_bytes,
        &stored.submit_intent_sig,
    )
    .map_err(|_| ApiError::Conflict("stored submission intent signature is invalid".into()))?;

    // ---- sandbox execution (typed Unsupported => HTTP 501) -----------------
    let receipt_hex = &req.submission_receipt;
    let rootfs_dir = state
        .config()
        .work_dir
        .join(format!("rootfs-{receipt_hex}"));
    let work_dir = state.config().work_dir.join(format!("work-{receipt_hex}"));
    let mut environment = None;
    let mut manifest = None;
    if let Some(source) = &state.config().artifact_source {
        let hash = req
            .manifest_sha256
            .as_deref()
            .filter(|h| valid_receipt(h))
            .ok_or_else(|| {
                ApiError::BadRequest("manifest_sha256 is required for artifact retrieval".into())
            })?;
        std::fs::create_dir_all(&state.config().work_dir)
            .map_err(|_| ApiError::Internal("could not prepare artifact directory".into()))?;
        let staged = crate::artifacts::fetch(
            source.as_ref(),
            crate::artifacts::Kind::Manifest,
            hash,
            &state.config().work_dir,
        )
        .await
        .map_err(store_error)?;
        let bytes = std::fs::read(staged.path()).map_err(|_| ApiError::StorageUnavailable)?;
        let parsed = crate::manifest::Manifest::parse(&bytes, &claimed.env_blob_sha256)
            .map_err(|e| ApiError::BadRequest(e.into()))?;
        if matches!(parsed.target, crate::manifest::Target::Binary { .. }) {
            return Err(ApiError::NotImplemented(
                "binary stdio target execution is not implemented".into(),
            ));
        }
        environment = Some(
            crate::artifacts::fetch(
                source.as_ref(),
                crate::artifacts::Kind::Environment,
                &claimed.env_blob_sha256,
                &state.config().work_dir,
            )
            .await
            .map_err(store_error)?,
        );
        manifest = Some(parsed);
    }
    let env_blob_path = environment
        .as_ref()
        .map(|file| file.path())
        .or_else(|| req.env_blob_path.as_deref().map(Path::new));
    let target_port = match manifest.as_ref().map(|m| &m.target) {
        Some(crate::manifest::Target::TcpService { port, .. }) => *port,
        _ => req.target_port.unwrap_or(1337),
    };
    let run_params = RunParams {
        rootfs_dir: &rootfs_dir,
        work_dir: &work_dir,
        exploit_py: &plaintext,
        env_blob_path,
        target_image: req.target_image.clone(),
        target_entrypoint: manifest
            .as_ref()
            .map(|m| m.entrypoint.clone())
            .unwrap_or_else(|| req.target_entrypoint.clone()),
        target_host: "target".to_string(),
        target_network: state.config().network.clone(),
        target_port,
        timeout_secs: manifest.as_ref().map_or(60, |m| m.limits.timeout_seconds),
        memory_mb: manifest.as_ref().map_or(512, |m| m.limits.memory_mb),
        cpus: 1.0,
        aslr_off: manifest
            .as_ref()
            .is_none_or(|m| m.determinism.aslr == "off"),
        seed: manifest
            .as_ref()
            .map_or(0, |m| i64::from(m.determinism.seed)),
    };

    match state.config().sandbox.run_exploit(&run_params).await {
        Err(SandboxError::Unsupported(w)) => {
            // Keep the encrypted object for restart recovery and retry.
            Err(ApiError::NotImplemented(format!(
                "sandbox unavailable: {w}"
            )))
        }
        Err(SandboxError::Timeout) => {
            let mut resp = fail_response(&state, &cv_bytes, &solver_bytes, &pda);
            resp.redacted_log = "execution timed out".to_string();
            Ok(Json(resp))
        }
        Err(e) => Err(ApiError::Internal(format!("sandbox failure: {e}"))),
        Ok(exec_outcome) => {
            let pass = exec_outcome.output.contains(flag.expose());
            // Execution output can contain challenge secrets or attacker data.
            // Never return it from the public runner API.
            let safe_log = if pass {
                "execution completed (PASS)"
            } else {
                "execution completed (FAIL)"
            };

            let response = if pass {
                let buyer_pk = crypto_box::PublicKey::from(cv_bytes.buyer_enc_pk);
                let ct = buyer_pk
                    .seal(&mut rand::rngs::OsRng, &plaintext)
                    .map_err(|e| {
                        ApiError::Internal(format!("sealed box encryption failed: {e}"))
                    })?;
                let ct_sha = sha2::Sha256::digest(&ct);
                VerifyResponse {
                    outcome: true,
                    sig: sign_verdict_b64(&state, &cv_bytes, &solver_bytes, &pda, true),
                    reveal_ciphertext: Some(base64::engine::general_purpose::STANDARD.encode(ct)),
                    reveal_ciphertext_url: None,
                    reveal_ciphertext_sha256: Some(hex::encode(ct_sha)),
                    redacted_log: safe_log.to_string(),
                }
            } else {
                let mut resp = fail_response(&state, &cv_bytes, &solver_bytes, &pda);
                resp.redacted_log = safe_log.to_string();
                return Ok(Json(resp));
            };
            // `Zeroizing` erases the enclave plaintext on every response path;
            // the immutable encrypted record remains for retry/restart safety.
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
            buyer_enc_pk: &cv.buyer_enc_pk,
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
