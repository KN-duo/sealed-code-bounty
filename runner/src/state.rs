//! Shared server state: master secret, verdict key, durable encrypted
//! submissions, and transient rate limiters.

use crate::config::Config;
use crate::flag;
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// The four chain-visible values the enclave cross-checks on /internal/verify.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChainView {
    pub env_blob_sha256: String,
    pub buyer_enc_pk: String,
    pub flag_commitment: String,
    pub exploit_sha256: String,
}

impl ChainView {
    /// Hex-decodes all fields into the byte forms used by the verdict signer.
    pub fn to_bytes(&self) -> Result<ChainViewBytes, String> {
        let d = |s: &str| -> Result<[u8; 32], String> {
            hex::decode(s)
                .map_err(|_| "chain view field is not hex".to_string())?
                .try_into()
                .map_err(|_| "chain view field must be 32 bytes".to_string())
        };
        Ok(ChainViewBytes {
            env_blob_sha256: d(&self.env_blob_sha256)?,
            buyer_enc_pk: d(&self.buyer_enc_pk)?,
            flag_commitment: d(&self.flag_commitment)?,
            exploit_sha256: d(&self.exploit_sha256)?,
        })
    }
}

pub struct ChainViewBytes {
    pub env_blob_sha256: [u8; 32],
    pub buyer_enc_pk: [u8; 32],
    pub flag_commitment: [u8; 32],
    pub exploit_sha256: [u8; 32],
}

/// Token bucket (capacity = window max, continuous refill).
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    updated_secs: f64,
}

impl TokenBucket {
    fn new(max: u32, now: f64) -> Self {
        Self {
            tokens: max as f64,
            updated_secs: now,
        }
    }
    fn take(&mut self, max: u32, window_secs: u64, now: f64) -> bool {
        let rate = max as f64 / window_secs as f64;
        self.tokens = (self.tokens + (now - self.updated_secs) * rate).min(max as f64);
        self.updated_secs = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct AppState {
    cfg: Config,
    master_secret: [u8; 32],
    verdict_key: SigningKey,
    submissions: Arc<dyn crate::submission_store::SubmissionStore>,
    /// Exactly one sandbox may execute at a time, including direct API calls.
    verification: tokio::sync::Mutex<()>,
    wallet_buckets: Mutex<HashMap<String, TokenBucket>>,
    ip_buckets: Mutex<HashMap<String, TokenBucket>>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl AppState {
    pub fn new(cfg: Config) -> Self {
        let master_secret = cfg.master_secret;
        let verdict_key = SigningKey::from_bytes(&flag::derive_verdict_seed(&master_secret));
        let submissions = cfg.submission_store.clone();
        Self {
            cfg,
            master_secret,
            verdict_key,
            submissions,
            verification: tokio::sync::Mutex::new(()),
            wallet_buckets: Mutex::new(new_map()),
            ip_buckets: Mutex::new(new_map()),
        }
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn verdict_key(&self) -> &SigningKey {
        &self.verdict_key
    }

    pub fn master_secret(&self) -> &[u8; 32] {
        &self.master_secret
    }

    // ---- rate limiting -----------------------------------------------------

    /// Returns false when either bucket is exhausted (→ HTTP 429).
    pub fn rate_allow(&self, wallet_key: &str, ip: &str) -> bool {
        let now = now_unix() as f64;
        let mut wallets = self.wallet_buckets.lock().expect("wallet buckets");
        let w = wallets
            .entry(wallet_key.to_string())
            .or_insert_with(|| TokenBucket::new(self.cfg.rate_limit_max, now));
        if !w.take(
            self.cfg.rate_limit_max,
            self.cfg.rate_limit_window_secs,
            now,
        ) {
            return false;
        }
        drop(wallets);

        let mut ips = self.ip_buckets.lock().expect("ip buckets");
        let b = ips
            .entry(ip.to_string())
            .or_insert_with(|| TokenBucket::new(self.cfg.rate_limit_max, now));
        b.take(
            self.cfg.rate_limit_max,
            self.cfg.rate_limit_window_secs,
            now,
        )
    }

    // ---- durable encrypted submissions ------------------------------------

    pub async fn store_submission(
        &self,
        receipt: &str,
        submission: &crate::submission_store::StoredSubmission,
    ) -> Result<(), crate::submission_store::StoreError> {
        let bytes = serde_json::to_vec(submission)
            .map_err(|_| crate::submission_store::StoreError::Unavailable)?;
        self.submissions.put(receipt, &bytes).await
    }

    pub async fn load_submission(
        &self,
        receipt: &str,
    ) -> Result<crate::submission_store::StoredSubmission, crate::submission_store::StoreError>
    {
        let bytes = self.submissions.get(receipt).await?;
        let submission: crate::submission_store::StoredSubmission = serde_json::from_slice(&bytes)
            .map_err(|_| crate::submission_store::StoreError::HashMismatch)?;
        if submission.version != 1 {
            return Err(crate::submission_store::StoreError::HashMismatch);
        }
        Ok(submission)
    }

    /// Reject concurrent work with backpressure rather than starting another
    /// sandbox or retaining an unbounded queue of requests inside the runner.
    pub fn try_verification(&self) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        self.verification.try_lock().ok()
    }

    /// TTL sweeper for transient in-memory rate-limit buckets. Encrypted
    /// submissions are durable and must not expire while an on-chain bounty
    /// may still refer to them.
    pub fn sweep_expired(&self) -> usize {
        // Audit L3: evict rate-limit buckets idle for >2 windows so they do
        // not grow without bound. The IP bucket remains as a coarse backstop;
        // NAT users legitimately share it by design.
        let idle_secs = (self.cfg.rate_limit_window_secs * 2) as f64;
        let nowf = now_unix() as f64;
        self.wallet_buckets
            .lock()
            .expect("wallet buckets")
            .retain(|_, b| nowf - b.updated_secs < idle_secs);
        self.ip_buckets
            .lock()
            .expect("ip buckets")
            .retain(|_, b| nowf - b.updated_secs < idle_secs);
        0
    }

    /// Background sweeper task — spawned once at startup.
    pub fn spawn_sweeper(state: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                state.sweep_expired();
            }
        })
    }
}

fn new_map<K>() -> HashMap<K, TokenBucket> {
    HashMap::new()
}
