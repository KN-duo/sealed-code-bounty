//! Immutable encrypted objects. Receipts are SHA-256 of the exact stored bytes.
//! The directory backend is for development; Nitro uses the vsock helper and
//! parent S3 broker. Neither backend accepts URLs or plaintext submissions.

use async_trait::async_trait;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const MAX_OBJECT_BYTES: usize = 512 * 1024;
const MAX_HELPER_BYTES: u64 = 1024 * 1024;
const MAX_DIRECTORY_OBJECTS: usize = 10_000;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredSubmission {
    pub version: u8,
    pub bounty_pda: String,
    pub solver_pubkey: String,
    pub claimed_chain_view: crate::state::ChainView,
    pub submit_intent_sig: String,
    pub exploit_sealed_box: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    InvalidReceipt,
    NotFound,
    TooLarge,
    HashMismatch,
    Full,
    Unavailable,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose helper output, S3 response bodies or local paths.
        f.write_str(match self {
            Self::InvalidReceipt => "invalid submission receipt",
            Self::NotFound => "encrypted submission not found",
            Self::TooLarge => "encrypted submission exceeds object size limit",
            Self::HashMismatch => "encrypted submission integrity check failed",
            Self::Full => "encrypted submission storage is full",
            Self::Unavailable => "encrypted submission storage unavailable",
        })
    }
}

pub fn valid_receipt(receipt: &str) -> bool {
    receipt.len() == 64
        && receipt
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn receipt_for(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn validate_object(receipt: &str, bytes: &[u8]) -> Result<(), StoreError> {
    if !valid_receipt(receipt) {
        return Err(StoreError::InvalidReceipt);
    }
    if bytes.is_empty() || bytes.len() > MAX_OBJECT_BYTES {
        return Err(StoreError::TooLarge);
    }
    if receipt_for(bytes) != receipt {
        return Err(StoreError::HashMismatch);
    }
    Ok(())
}

#[async_trait]
pub trait SubmissionStore: Send + Sync {
    /// Return success only after durable storage accepts the complete object.
    async fn put(&self, receipt: &str, bytes: &[u8]) -> Result<(), StoreError>;
    async fn get(&self, receipt: &str) -> Result<Vec<u8>, StoreError>;
}

#[derive(Clone)]
pub struct DirectoryStore {
    inner: Arc<DirectoryInner>,
}

struct DirectoryInner {
    root: PathBuf,
    cap: u64,
    mutation: Mutex<()>,
}

impl DirectoryStore {
    pub fn new(root: PathBuf, cap: u64) -> Self {
        Self {
            inner: Arc::new(DirectoryInner {
                root,
                cap,
                mutation: Mutex::new(()),
            }),
        }
    }

    fn read_file(path: &Path) -> Result<Vec<u8>, StoreError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StoreError::NotFound
                } else {
                    StoreError::Unavailable
                }
            })?;
        let metadata = file.metadata().map_err(|_| StoreError::Unavailable)?;
        if !metadata.is_file() {
            return Err(StoreError::Unavailable);
        }
        if metadata.len() > MAX_OBJECT_BYTES as u64 {
            return Err(StoreError::TooLarge);
        }
        let mut bytes = Vec::new();
        file.take(MAX_OBJECT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| StoreError::Unavailable)?;
        if bytes.len() > MAX_OBJECT_BYTES {
            return Err(StoreError::TooLarge);
        }
        Ok(bytes)
    }

    fn usage(root: &Path) -> Result<(u64, usize), StoreError> {
        let mut bytes = 0u64;
        let mut count = 0usize;
        for entry in std::fs::read_dir(root).map_err(|_| StoreError::Unavailable)? {
            let entry = entry.map_err(|_| StoreError::Unavailable)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(StoreError::Unavailable);
            };
            if name == ".lock" {
                continue;
            }
            let metadata =
                std::fs::symlink_metadata(entry.path()).map_err(|_| StoreError::Unavailable)?;
            if !metadata.is_file() {
                return Err(StoreError::Unavailable);
            }
            // Include abandoned temporary files in the quota after a crash.
            bytes = bytes.checked_add(metadata.len()).ok_or(StoreError::Full)?;
            count += 1;
        }
        Ok((bytes, count))
    }

    fn put_sync(&self, receipt: &str, bytes: &[u8]) -> Result<(), StoreError> {
        validate_object(receipt, bytes)?;
        let _guard = self
            .inner
            .mutation
            .lock()
            .map_err(|_| StoreError::Unavailable)?;
        std::fs::create_dir_all(&self.inner.root).map_err(|_| StoreError::Unavailable)?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.inner.root.join(".lock"))
            .map_err(|_| StoreError::Unavailable)?;
        use std::os::fd::AsRawFd;
        // Serialize quota admission across processes; closing the file releases
        // the advisory lock on every return path. This backend targets Linux.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(StoreError::Unavailable);
        }
        let destination = self.inner.root.join(format!("{receipt}.json"));
        match Self::read_file(&destination) {
            Ok(existing) => {
                validate_object(receipt, &existing)?;
                // Retry after a previous directory fsync failure still waits
                // for directory durability before returning acknowledgement.
                return std::fs::File::open(&self.inner.root)
                    .and_then(|dir| dir.sync_all())
                    .map_err(|_| StoreError::Unavailable);
            }
            Err(StoreError::NotFound) => {}
            Err(error) => return Err(error),
        }
        let (used, count) = Self::usage(&self.inner.root)?;
        if bytes.len() as u64 > self.inner.cap.saturating_sub(used)
            || count >= MAX_DIRECTORY_OBJECTS
        {
            return Err(StoreError::Full);
        }
        let mut temporary = tempfile::NamedTempFile::new_in(&self.inner.root)
            .map_err(|_| StoreError::Unavailable)?;
        temporary
            .write_all(bytes)
            .and_then(|_| temporary.as_file().sync_all())
            .map_err(|_| StoreError::Unavailable)?;
        temporary
            .persist_noclobber(destination)
            .map_err(|_| StoreError::Unavailable)?;
        std::fs::File::open(&self.inner.root)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| StoreError::Unavailable)
    }
}

#[async_trait]
impl SubmissionStore for DirectoryStore {
    async fn put(&self, receipt: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let store = self.clone();
        let receipt = receipt.to_owned();
        let bytes = bytes.to_vec();
        tokio::task::spawn_blocking(move || store.put_sync(&receipt, &bytes))
            .await
            .map_err(|_| StoreError::Unavailable)?
    }

    async fn get(&self, receipt: &str) -> Result<Vec<u8>, StoreError> {
        if !valid_receipt(receipt) {
            return Err(StoreError::InvalidReceipt);
        }
        let path = self.inner.root.join(format!("{receipt}.json"));
        let receipt = receipt.to_owned();
        tokio::task::spawn_blocking(move || {
            let bytes = Self::read_file(&path)?;
            validate_object(&receipt, &bytes)?;
            Ok(bytes)
        })
        .await
        .map_err(|_| StoreError::Unavailable)?
    }
}

/// The helper is part of the measured enclave image. It contains only a fixed
/// parent-vsock client. Credentials and plaintext are never passed to it.
pub struct VsockStore {
    helper: PathBuf,
}

impl VsockStore {
    pub fn new(helper: PathBuf) -> Self {
        Self { helper }
    }

    pub(crate) async fn request(
        &self,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, StoreError> {
        let payload = serde_json::to_vec(&request).map_err(|_| StoreError::Unavailable)?;
        let mut child = tokio::process::Command::new("python3")
            .arg(&self.helper)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| StoreError::Unavailable)?;
        let mut stdin = child.stdin.take().ok_or(StoreError::Unavailable)?;
        let stdout = child.stdout.take().ok_or(StoreError::Unavailable)?;
        let operation = async {
            stdin
                .write_all(&payload)
                .await
                .map_err(|_| StoreError::Unavailable)?;
            stdin
                .shutdown()
                .await
                .map_err(|_| StoreError::Unavailable)?;
            drop(stdin);
            let mut output = Vec::new();
            stdout
                .take(MAX_HELPER_BYTES + 1)
                .read_to_end(&mut output)
                .await
                .map_err(|_| StoreError::Unavailable)?;
            if output.len() as u64 > MAX_HELPER_BYTES {
                return Err(StoreError::TooLarge);
            }
            let status = child.wait().await.map_err(|_| StoreError::Unavailable)?;
            // The helper may exit nonzero with a typed error response.
            let value: serde_json::Value =
                serde_json::from_slice(&output).map_err(|_| StoreError::Unavailable)?;
            if value.get("ok").and_then(|v| v.as_bool()) != Some(true) {
                return Err(match value.get("error").and_then(|v| v.as_str()) {
                    Some("not_found") => StoreError::NotFound,
                    Some("too_large") => StoreError::TooLarge,
                    Some("hash_mismatch") => StoreError::HashMismatch,
                    Some("storage_full") => StoreError::Full,
                    Some("invalid_request") => StoreError::InvalidReceipt,
                    _ => StoreError::Unavailable,
                });
            }
            if !status.success() {
                return Err(StoreError::Unavailable);
            }
            Ok(value)
        };
        let result = tokio::time::timeout(Duration::from_secs(15), operation)
            .await
            .unwrap_or(Err(StoreError::Unavailable));
        if result.is_err() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        result
    }
}

#[async_trait]
impl SubmissionStore for VsockStore {
    async fn put(&self, receipt: &str, bytes: &[u8]) -> Result<(), StoreError> {
        validate_object(receipt, bytes)?;
        self.request(serde_json::json!({
            "op": "put", "receipt": receipt,
            "body_b64": base64::engine::general_purpose::STANDARD.encode(bytes),
        }))
        .await?;
        Ok(())
    }

    async fn get(&self, receipt: &str) -> Result<Vec<u8>, StoreError> {
        if !valid_receipt(receipt) {
            return Err(StoreError::InvalidReceipt);
        }
        let value = self
            .request(serde_json::json!({"op": "get", "receipt": receipt}))
            .await?;
        let encoded = value
            .get("body_b64")
            .and_then(|v| v.as_str())
            .ok_or(StoreError::Unavailable)?;
        if encoded.len() > MAX_OBJECT_BYTES.div_ceil(3) * 4 {
            return Err(StoreError::TooLarge);
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| StoreError::Unavailable)?;
        validate_object(receipt, &bytes)?;
        Ok(bytes)
    }
}
