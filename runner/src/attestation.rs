//! Fresh NSM evidence binding both application keys and the measured build.
//! No software fallback: a machine without /dev/nsm cannot attest.

use crate::{error::ApiError, state::AppState};
use aws_nitro_enclaves_nsm_api::{
    api::{Request, Response},
    driver::{nsm_exit, nsm_init, nsm_process_request},
};
use axum::{extract::State, http::header, response::IntoResponse, Json};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub const PROTOCOL: &str = "SCB_VERDICT_V5";
pub const BUILD_COMMIT: &str = match option_env!("SCB_BUILD_COMMIT") {
    Some(commit) => commit,
    None => "development",
};
static ADMISSION: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationRequest {
    pub nonce_b64: String,
}

#[derive(Serialize)]
pub struct AttestationResponse {
    pub attestation_version: u8,
    pub document_b64: String,
    pub nonce_b64: String,
    pub enclave_enc_pubkey_hex: String,
    pub verdict_pubkey_hex: String,
    pub build_commit: &'static str,
    pub protocol: &'static str,
}

fn valid_build_commit(commit: &str) -> bool {
    if commit == "development" {
        return true;
    }
    let hash = commit.strip_suffix("-dirty").unwrap_or(commit);
    hash.len() == 40
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Binary layout shared with nitro/verify_attestation.py. Only public data.
fn key_binding(verdict_key: &[u8; 32]) -> Result<Vec<u8>, ApiError> {
    if !valid_build_commit(BUILD_COMMIT) {
        return Err(ApiError::AttestationUnavailable);
    }
    let mut binding = b"SCB_ATTESTATION_V1\0".to_vec();
    binding.extend_from_slice(verdict_key);
    binding.extend_from_slice(BUILD_COMMIT.as_bytes());
    binding.push(0);
    binding.extend_from_slice(PROTOCOL.as_bytes());
    Ok(binding)
}

struct NsmHandle(i32);

impl Drop for NsmHandle {
    fn drop(&mut self) {
        nsm_exit(self.0);
    }
}

fn document(nonce: Vec<u8>, public_key: [u8; 32], binding: Vec<u8>) -> Result<Vec<u8>, ApiError> {
    let fd = nsm_init();
    if fd < 0 {
        return Err(ApiError::AttestationUnavailable);
    }
    let device = NsmHandle(fd);
    match nsm_process_request(
        device.0,
        Request::Attestation {
            nonce: Some(nonce.into()),
            public_key: Some(public_key.to_vec().into()),
            user_data: Some(binding.into()),
        },
    ) {
        Response::Attestation { document } if !document.is_empty() && document.len() <= 16_384 => {
            Ok(document)
        }
        _ => Err(ApiError::AttestationUnavailable),
    }
}

pub async fn attest(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AttestationRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Check encoded size before allocating. Require canonical padded base64.
    if request.nonce_b64.len() > 88 {
        return Err(ApiError::BadRequest(
            "nonce must contain 16 to 64 bytes".into(),
        ));
    }
    let nonce = STANDARD
        .decode(&request.nonce_b64)
        .map_err(|_| ApiError::BadRequest("nonce_b64 must be canonical base64".into()))?;
    if !(16..=64).contains(&nonce.len()) || STANDARD.encode(&nonce) != request.nonce_b64 {
        return Err(ApiError::BadRequest(
            "nonce must contain 16 to 64 bytes".into(),
        ));
    }
    // A blocked NSM ioctl must not admit unlimited worker threads. This permit
    // is owned by the blocking operation even if the HTTP client disconnects.
    let permit = ADMISSION
        .try_acquire()
        .map_err(|_| ApiError::AttestationUnavailable)?;
    let encryption_key = *state.config().enclave_enc_secret.public_key().as_bytes();
    let verdict_key = state.verdict_key().verifying_key().to_bytes();
    let binding = key_binding(&verdict_key)?;
    let signed = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        document(nonce, encryption_key, binding)
    })
    .await
    .map_err(|_| ApiError::AttestationUnavailable)??;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(AttestationResponse {
            attestation_version: 1,
            document_b64: STANDARD.encode(signed),
            nonce_b64: request.nonce_b64,
            enclave_enc_pubkey_hex: hex::encode(encryption_key),
            verdict_pubkey_hex: hex::encode(verdict_key),
            build_commit: BUILD_COMMIT,
            protocol: PROTOCOL,
        }),
    ))
}
