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
    /// Rate limit: max submissions per wallet AND per IP inside the window.
    pub rate_limit_max: u32,
    /// Rate limit window in seconds (default config: 5 per hour).
    pub rate_limit_window_secs: u64,
    /// Loopback-only docker network shared by target+exploit containers.
    pub network: String,
    /// Enclave X25519 secret key — hunters seal exploit uploads to the
    /// matching public key pinned in Config.enclave_enc_pk on-chain.
    pub enclave_enc_secret: crypto_box::SecretKey,
    pub sandbox: Arc<dyn SandboxExecutor + Send + Sync>,
    /// Immutable store for ciphertext and validated public upload metadata.
    pub submission_store: Arc<dyn crate::submission_store::SubmissionStore>,
    /// Required in vsock mode: verified, fixed-key target artifacts.
    pub artifact_source: Option<Arc<dyn crate::artifacts::ArtifactSource>>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print master_secret.
        f.debug_struct("Config")
            .field("port", &self.port)
            .field("work_dir", &self.work_dir)
            .field("storage_cap_bytes", &self.storage_cap_bytes)
            .field("rate_limit_max", &self.rate_limit_max)
            .field("rate_limit_window_secs", &self.rate_limit_window_secs)
            .field("has_enclave_enc_secret", &true)
            .finish_non_exhaustive()
    }
}

/// Raw option strings for the programmatic constructor.
pub struct BuildOpts {
    pub port: Option<String>,
    pub network: Option<String>,
    pub master_hex: Option<String>,
    pub enc_secret_hex: Option<String>,
    pub work_dir: Option<String>,
    pub storage_cap: Option<String>,
    pub rate_max: Option<String>,
    pub rate_window: Option<String>,
    /// Programmatic constructor defaults to a temporary development store.
    pub submission_store: Option<Arc<dyn crate::submission_store::SubmissionStore>>,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let backend = std::env::var("SCB_SUBMISSION_STORE").map_err(|_| {
            "SCB_SUBMISSION_STORE must be explicitly set to vsock or development-directory"
                .to_string()
        })?;
        let mut cfg = Self::build(BuildOpts {
            port: std::env::var("PORT").ok(),
            master_hex: std::env::var("SCB_MASTER_SECRET_HEX").ok(),
            enc_secret_hex: std::env::var("SCB_ENCLAVE_ENC_SECRET_HEX").ok(),
            work_dir: std::env::var("SCB_WORK_DIR").ok(),
            storage_cap: std::env::var("SCB_STORAGE_CAP_BYTES").ok(),
            rate_max: std::env::var("SCB_RATE_LIMIT_MAX").ok(),
            rate_window: std::env::var("SCB_RATE_LIMIT_WINDOW_SECS").ok(),
            submission_store: None,
            network: Some(std::env::var("SCB_NETWORK").unwrap_or_else(|_| "scb-loopback".into())),
        })?;
        cfg.submission_store = match backend.as_str() {
            "vsock" => Arc::new(crate::submission_store::VsockStore::new(
                std::env::var_os("SCB_STORAGE_HELPER")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("/app/nitro/storage_client.py")),
            )),
            "development-directory"
                if std::env::var("SCB_ALLOW_DEV_DIRECTORY_STORE").as_deref() == Ok("1") =>
            {
                let root = std::env::var_os("SCB_SUBMISSION_DIRECTORY")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| cfg.work_dir.join("submissions"));
                Arc::new(crate::submission_store::DirectoryStore::new(
                    root,
                    cfg.storage_cap_bytes,
                ))
            }
            "development-directory" => {
                return Err(
                    "development-directory storage requires SCB_ALLOW_DEV_DIRECTORY_STORE=1".into(),
                )
            }
            _ => return Err("SCB_SUBMISSION_STORE must be vsock or development-directory".into()),
        };
        if backend == "vsock" {
            cfg.artifact_source = Some(Arc::new(crate::submission_store::VsockStore::new(
                std::env::var_os("SCB_STORAGE_HELPER")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("/app/nitro/storage_client.py")),
            )));
        }
        Ok(cfg)
    }

    /// Test/programmatic constructor.
    pub fn build(o: super::config::BuildOpts) -> Result<Self, String> {
        let BuildOpts {
            port,
            master_hex,
            enc_secret_hex,
            work_dir,
            storage_cap,
            rate_max,
            rate_window,
            submission_store,
            network,
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

        let parse_num = |raw: &Option<String>, dflt: u64, name: &str| -> Result<u64, String> {
            match raw {
                Some(v) => v
                    .parse::<u64>()
                    .map_err(|_| format!("{name} must be an integer")),
                None => Ok(dflt),
            }
        };
        let work_dir = work_dir
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp/scb-runner"));
        let storage_cap_bytes = parse_num(&storage_cap, 16 * 1024 * 1024, "SCB_STORAGE_CAP_BYTES")?;
        let rate_limit_max = u32::try_from(parse_num(&rate_max, 5, "SCB_RATE_LIMIT_MAX")?)
            .map_err(|_| "rate limit too large")?;
        let rate_limit_window_secs =
            parse_num(&rate_window, 60 * 60, "SCB_RATE_LIMIT_WINDOW_SECS")?;

        // Task 9: SCB_SANDBOX=docker|stub (default stub).
        let sandbox_name = std::env::var("SCB_SANDBOX").unwrap_or_else(|_| "stub".into());
        let sandbox: Arc<dyn SandboxExecutor + Send + Sync> = match sandbox_name.as_str() {
            "docker" => Arc::new(crate::sandbox::DockerCli::from_env()?),
            "stub" => Arc::new(crate::sandbox::StubSandbox),
            other => return Err(format!("SCB_SANDBOX must be docker|stub, got \"{other}\"")),
        };

        let submission_store = submission_store.unwrap_or_else(|| {
            Arc::new(crate::submission_store::DirectoryStore::new(
                work_dir.join("submissions"),
                storage_cap_bytes,
            ))
        });

        Ok(Self {
            port,
            master_secret,
            enclave_enc_secret,
            work_dir,
            storage_cap_bytes,
            rate_limit_max,
            rate_limit_window_secs,
            network: network.unwrap_or_else(|| "scb-loopback".into()),
            sandbox,
            submission_store,
            artifact_source: None,
        })
    }
}

fn decode_master_hex(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s.trim()).map_err(|_| "SCB_MASTER_SECRET_HEX must be valid hex")?;
    bytes.try_into().map_err(|_| {
        format!(
            "SCB_MASTER_SECRET_HEX must be exactly 64 hex chars (32 bytes), got {} chars",
            s.trim().len()
        )
    })
}
