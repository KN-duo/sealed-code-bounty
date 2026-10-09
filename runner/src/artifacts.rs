//! Bounded artifact retrieval. The untrusted parent chooses neither paths nor URLs.
use crate::submission_store::{valid_receipt, StoreError, VsockStore};
use async_trait::async_trait;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::{io::Write, path::Path, time::Duration};

pub const CHUNK_BYTES: usize = 512 * 1024;
pub const MANIFEST_CAP: u64 = 64 * 1024;
pub const ENVIRONMENT_CAP: u64 = 128 * 1024 * 1024;

#[derive(Clone, Copy)]
pub enum Kind {
    Manifest,
    Environment,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::Environment => "environment",
        }
    }
    fn cap(self) -> u64 {
        match self {
            Self::Manifest => MANIFEST_CAP,
            Self::Environment => ENVIRONMENT_CAP,
        }
    }
}
pub struct Chunk {
    pub offset: u64,
    pub total_bytes: u64,
    pub bytes: Vec<u8>,
}

#[async_trait]
pub trait ArtifactSource: Send + Sync {
    async fn chunk(&self, kind: Kind, hash: &str, offset: u64) -> Result<Chunk, StoreError>;
}

#[async_trait]
impl ArtifactSource for VsockStore {
    async fn chunk(&self, kind: Kind, hash: &str, offset: u64) -> Result<Chunk, StoreError> {
        if !valid_receipt(hash) || offset >= kind.cap() {
            return Err(StoreError::InvalidReceipt);
        }
        let value = self.request(serde_json::json!({"op":"get_artifact", "kind":kind.name(), "sha256":hash, "offset":offset})).await?;
        let obj = value.as_object().ok_or(StoreError::Unavailable)?;
        if obj.len() != 4 {
            return Err(StoreError::Unavailable);
        }
        let encoded = value["body_b64"].as_str().ok_or(StoreError::Unavailable)?;
        if encoded.len() > CHUNK_BYTES.div_ceil(3) * 4 {
            return Err(StoreError::TooLarge);
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| StoreError::Unavailable)?;
        Ok(Chunk {
            offset: value["offset"].as_u64().ok_or(StoreError::Unavailable)?,
            total_bytes: value["total_bytes"]
                .as_u64()
                .ok_or(StoreError::Unavailable)?,
            bytes,
        })
    }
}

/// The temporary file is never made visible to the sandbox until all bytes hash
/// correctly. Cancellation and every error drop and remove it automatically.
pub async fn fetch(
    source: &dyn ArtifactSource,
    kind: Kind,
    hash: &str,
    directory: &Path,
) -> Result<tempfile::NamedTempFile, StoreError> {
    if !valid_receipt(hash) {
        return Err(StoreError::InvalidReceipt);
    }
    let operation = async {
        let mut staged =
            tempfile::NamedTempFile::new_in(directory).map_err(|_| StoreError::Unavailable)?;
        let mut offset = 0;
        let mut total = None;
        let mut digest = Sha256::new();
        loop {
            let chunk = source.chunk(kind, hash, offset).await?;
            if chunk.total_bytes == 0 || chunk.total_bytes > kind.cap() {
                return Err(StoreError::TooLarge);
            }
            if chunk.offset != offset
                || offset >= chunk.total_bytes
                || total.is_some_and(|n| n != chunk.total_bytes)
                || chunk.bytes.len() as u64 != (chunk.total_bytes - offset).min(CHUNK_BYTES as u64)
            {
                return Err(StoreError::Unavailable);
            }
            total = Some(chunk.total_bytes);
            digest.update(&chunk.bytes);
            staged
                .write_all(&chunk.bytes)
                .map_err(|_| StoreError::Unavailable)?;
            offset += chunk.bytes.len() as u64;
            if offset == chunk.total_bytes {
                break;
            }
        }
        if hex::encode(digest.finalize()) != hash {
            return Err(StoreError::HashMismatch);
        }
        staged.flush().map_err(|_| StoreError::Unavailable)?;
        Ok(staged)
    };
    tokio::time::timeout(Duration::from_secs(120), operation)
        .await
        .unwrap_or(Err(StoreError::Unavailable))
}
