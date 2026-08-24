//! Environment configuration. Fails fast with actionable messages.

use crate::sandbox::SandboxExecutor;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone)]
pub struct Config {
    pub port: u16,
    /// Master secret `M` — the root of all flag material (D14). 32 bytes.
    pub master_secret: [u8; 32],
    /// Directory used for unpacked rootfs copies and uploaded blob staging.
    pub work_dir: PathBuf,
    /// Global cap on stored upload bytes (backpressure → HTTP 503).
    pub storage_cap_bytes: u64,
    /// Uploads not registered on-chain within this window are purged.
    pub blob_ttl_secs: u64,
    /// Rate limit: max submissions per wallet AND per IP inside the window.
    pub rate_limit_max: u32,
    /// Rate limit window in seconds (default config: 5 per hour).
    pub rate_limit_window_secs: u64,
    /// Enclave X25519 secret key — hunters seal exploit uploads to the
    /// matching public key pinned in Config.enclave_enc_pk on-chain.
    pub enclave_enc_secret: crypto_box::SecretKey,
    #[allow(dead_code)] // wired into verify once blob pulling lands
    pub sandbox: Arc<dyn SandboxExecutor + Send + Sync>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print master_secret.
        f.debug_struct("Config")
            .field("port", &self.port)
            .field("work_dir", &self.work_dir)
            .field("storage_cap_bytes", &self.storage_cap_bytes)
            .field("blob_ttl_secs", &self.blob_ttl_secs)
            .field("rate_limit_max", &self.rate_limit_max)
            .field("rate_limit_window_secs", &self.rate_limit_window_secs)
            .field("has_enclave_enc_secret", &true)
            .finish_non_exhaustive()
    }
}

/// Raw option strings for the programmatic constructor.
pub struct BuildOpts {
    pub port: Option<String>,
    pub master_hex: Option<String>,
    pub enc_secret_hex: Option<String>,
    pub work_dir: Option<String>,
    pub storage_cap: Option<String>,
    pub blob_ttl: Option<String>,
    pub rate_max: Option<String>,
    pub rate_window: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Self::build(BuildOpts {
            port: std::env::var("PORT").ok(),
            master_hex: std::env::var("SCB_MASTER_SECRET_HEX").ok(),
            enc_secret_hex: std::env::var("SCB_ENCLAVE_ENC_SECRET_HEX").ok(),
            work_dir: std::env::var("SCB_WORK_DIR").ok(),
            storage_cap: std::env::var("SCB_STORAGE_CAP_BYTES").ok(),
            blob_ttl: std::env::var("SCB_BLOB_TTL_SECS").ok(),
            rate_max: std::env::var("SCB_RATE_LIMIT_MAX").ok(),
            rate_window: std::env::var("SCB_RATE_LIMIT_WINDOW_SECS").ok(),
        })
    }

    /// Test/programmatic constructor.
    pub fn build(o: super::config::BuildOpts) -> Result<Self, String> {
        let BuildOpts {
            port,
            master_hex,
            enc_secret_hex,
            work_dir,
            storage_cap,
            blob_ttl,
            rate_max,
            rate_window,
        } = o;
        let port = match port {
            Some(v) => v.parse::<u16>().map_err(|_| "PORT must be a u16")?,
            None => 8443,
        };

        let hex_str = master_hex.ok_or(
            "SCB_MASTER_SECRET_HEX is required: 64 hex chars = 32-byte master secret M. \
             It never leaves the enclave; losing it only means flags rotate.",
        )?;
        let master_secret = decode_master_hex(&hex_str)?;

        let enc_hex = enc_secret_hex.ok_or(
            "SCB_ENCLAVE_ENC_SECRET_HEX is required: 64 hex chars = X25519 secret key whose \
             public half is pinned as Config.enclave_enc_pk on-chain",
        )?;
        let enc_bytes: [u8; 32] = hex::decode(enc_hex.trim())
            .map_err(|_| "SCB_ENCLAVE_ENC_SECRET_HEX must be valid hex")?
            .try_into()
            .map_err(|_| "SCB_ENCLAVE_ENC_SECRET_HEX must be exactly 64 hex chars")?;
        let enclave_enc_secret = crypto_box::SecretKey::from(enc_bytes);

        let work_dir = work_dir.map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp/scb-runner"));

        let parse_num = |raw: &Option<String>, dflt: u64, name: &str| -> Result<u64, String> {
            match raw {
                Some(v) => v.parse::<u64>().map_err(|_| format!("{name} must be an integer")),
                None => Ok(dflt),
            }
        };
        let storage_cap_bytes = parse_num(&storage_cap, 2 * 1024 * 1024 * 1024, "SCB_STORAGE_CAP_BYTES")?;
        let blob_ttl_secs = parse_num(&blob_ttl, 30 * 60, "SCB_BLOB_TTL_SECS")?;
        let rate_limit_max =
            u32::try_from(parse_num(&rate_max, 5, "SCB_RATE_LIMIT_MAX")?).map_err(|_| "rate limit too large")?;
        let rate_limit_window_secs = parse_num(&rate_window, 60 * 60, "SCB_RATE_LIMIT_WINDOW_SECS")?;

        Ok(Self {
            port,
            master_secret,
            enclave_enc_secret,
            work_dir,
            storage_cap_bytes,
            blob_ttl_secs,
            rate_limit_max,
            rate_limit_window_secs,
            sandbox: Arc::new(crate::sandbox::StubSandbox),
        })
    }
}

fn decode_master_hex(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s.trim())
        .map_err(|_| "SCB_MASTER_SECRET_HEX must be valid hex")?;
    bytes
        .try_into()
        .map_err(|_| format!("SCB_MASTER_SECRET_HEX must be exactly 64 hex chars (32 bytes), got {} chars", s.trim().len()))
}
