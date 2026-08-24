//! Shared server state: master secret, verdict key, upload store, rate
//! limiters, storage-cap accounting, TTL sweeper.

use crate::config::Config;
use crate::flag;
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// The four chain-visible values the enclave cross-checks on /internal/verify.
#[derive(Debug, Clone, serde::Deserialize)]
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

#[derive(Debug, Clone)]
pub struct BlobRecord {
    pub solver_pubkey_b58: String,
    /// Bounty PDA (base58) this upload belongs to.
    pub bounty_pda_b58: String,
    /// Plaintext exploit — lives only in this process's memory.
    pub plaintext: Vec<u8>,
    pub chain_view: ChainView,
    pub created_at: u64,
    /// Flipped when /internal/verify consumes the blob (TTL sweeper skips it).
    pub registered: bool,
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
    uploads: Mutex<HashMap<String /*receipt hex*/, BlobRecord>>,
    /// bounty_pda b58 -> receipt hex (newest wins).
    latest_by_bounty: Mutex<HashMap<String, String>>,
    wallet_buckets: Mutex<HashMap<String, TokenBucket>>,
    ip_buckets: Mutex<HashMap<String, TokenBucket>>,
    storage_used: AtomicU64,
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
        Self {
            cfg,
            master_secret,
            verdict_key,
            uploads: Mutex::new(HashMap::new()),
            latest_by_bounty: Mutex::new(HashMap::new()),
            wallet_buckets: Mutex::new(new_map()),
            ip_buckets: Mutex::new(new_map()),
            storage_used: AtomicU64::new(0),
        }
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn verdict_key(&self) -> &SigningKey {
        &self.verdict_key
    }

    /// Current reserved storage bytes (test/ops visibility).
    pub fn storage_used(&self) -> u64 {
        self.storage_used.load(Ordering::SeqCst)
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

    // ---- storage accounting ------------------------------------------------

    /// Reserves `bytes` against the global cap → false means HTTP 503.
    pub fn storage_try_reserve(&self, bytes: u64) -> bool {
        loop {
            let cur = self.storage_used.load(Ordering::SeqCst);
            if cur + bytes > self.cfg.storage_cap_bytes {
                return false;
            }
            match self.storage_used.compare_exchange(
                cur,
                cur + bytes,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }

    pub fn storage_release(&self, bytes: u64) {
        self.storage_used.fetch_sub(bytes, Ordering::SeqCst);
    }

    // ---- uploads -----------------------------------------------------------

    pub fn store_upload(&self, bounty_pda_b58: &str, receipt_hex: String, record: BlobRecord) {
        self.latest_by_bounty
            .lock()
            .expect("latest map")
            .insert(bounty_pda_b58.to_string(), receipt_hex.clone());
        self.uploads.lock().expect("uploads").insert(receipt_hex, record);
    }

    /// Peeks the newest upload for a bounty WITHOUT consuming it.
    pub fn peek_latest_upload_for_bounty(
        &self,
        bounty_pda_b58: &str,
    ) -> Option<(String, BlobRecord)> {
        let key = {
            let m = self.latest_by_bounty.lock().expect("latest map");
            m.get(bounty_pda_b58).cloned()
        }?;
        let rec = self.uploads.lock().expect("uploads").get(&key).cloned();
        rec.map(|r| (key, r))
    }

    /// Consumes (removes + releases storage) an upload once its verdict has
    /// been produced. The caller MUST zeroize the returned plaintext buffer
    /// before dropping it. Fixes audit M1 (uploads never freed).
    pub fn consume_upload(&self, receipt_hex: &str) -> Option<BlobRecord> {
        let rec = {
            let mut uploads = self.uploads.lock().expect("uploads");
            uploads.remove(receipt_hex)?
        };
        self.storage_release(rec.plaintext.len() as u64);
        self.latest_by_bounty
            .lock()
            .expect("latest map")
            .retain(|_, v| v != receipt_hex);
        Some(rec)
    }

    /// TTL sweeper: purge unregistered uploads older than the window.
    /// Returns number purged. Registered blobs are exempt.
    pub fn sweep_expired(&self) -> usize {
        let now = now_unix();
        let cutoff = now.saturating_sub(self.cfg.blob_ttl_secs);
        let mut purged = 0usize;
        {
            let mut uploads = self.uploads.lock().expect("uploads");
            let expired: Vec<String> = uploads
                .iter()
                .filter(|(_, r)| !r.registered && r.created_at < cutoff)
                .map(|(k, _)| k.clone())
                .collect();
            for key in expired {
                if let Some(rec) = uploads.remove(&key) {
                    self.storage_release(rec.plaintext.len() as u64);
                    self.latest_by_bounty
                        .lock()
                        .expect("latest map")
                        .retain(|_, v| v != &key);
                    purged += 1;
                }
            }
        }
        // Audit L3: evict rate-limit buckets idle for >2 windows so they do
        // not grow without bound. The IP bucket remains as a coarse backstop;
        // NAT users legitimately share it by design.
        let idle_secs = (self.cfg.rate_limit_window_secs * 2) as f64;
        let nowf = now as f64;
        self.wallet_buckets
            .lock()
            .expect("wallet buckets")
            .retain(|_, b| nowf - b.updated_secs < idle_secs);
        self.ip_buckets
            .lock()
            .expect("ip buckets")
            .retain(|_, b| nowf - b.updated_secs < idle_secs);
        purged
    }

    /// Background sweeper task — spawned once at startup.
    pub fn spawn_sweeper(state: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let n = state.sweep_expired();
                if n > 0 {
                    tracing::info!(purged = n, "TTL sweeper purged unregistered uploads");
                }
            }
        })
    }
}

fn new_map<K>() -> HashMap<K, TokenBucket> {
    HashMap::new()
}


