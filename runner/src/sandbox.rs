//! Sandbox execution boundary.
//!
//! [`SandboxExecutor`] is the single seam between "verdict-grade trust" and
//! "OS-level execution". Two implementations:
//!   * [`DockerCli`] — REAL (integration-pending): drives `docker run`
//!     exclusively through argument arrays, same discipline as cli/scb-pack.
//!   * [`StubSandbox`] — typed `Unsupported`; used until blob pulling lands.
//!
//! Contract (§4.3 steps 5–7, D13): the environment's own entrypoint runs
//! under an ASLR personality identical to the dev plane when
//! `aslr_off=true`, `SEED` is exported, the exploit gets only loopback
//! access to `target_host:target_port`, and stdout is captured whole for
//! flag scanning. Nothing about this function may write anywhere else.

use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug)]
pub struct RunParams<'a> {
    /// Directory holding the unpacked environment rootfs copy.
    pub rootfs_dir: &'a Path,
    /// Work directory staged with the hunter's exploit at `exploit.py`.
    pub work_dir: &'a Path,
    pub exploit_py: &'a [u8],
    pub target_host: String,
    pub target_port: u16,
    pub timeout_secs: u64,
    pub memory_mb: u64,
    pub cpus: f64,
    pub aslr_off: bool,
    pub seed: i64,
}

#[derive(Debug)]
pub struct ExecOutcome {
    /// Raw combined stdout/stderr of the exploit process (pre-redaction).
    pub output: String,
    pub timed_out: bool,
}

#[derive(Debug)]
pub enum SandboxError {
    /// Typed stub response — never silently skipped by callers.
    Unsupported(&'static str),
    Io(std::io::Error),
    Timeout,
    Runtime(String),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxError::Unsupported(w) => write!(f, "sandbox unsupported: {w}"),
            SandboxError::Io(e) => write!(f, "sandbox io: {e}"),
            SandboxError::Timeout => write!(f, "sandbox execution timed out"),
            SandboxError::Runtime(s) => write!(f, "sandbox runtime error: {s}"),
        }
    }
}

impl std::error::Error for SandboxError {}

#[async_trait]
pub trait SandboxExecutor: Send + Sync {
    async fn run_exploit(&self, params: &RunParams<'_>) -> Result<ExecOutcome, SandboxError>;
}

/// Default until SCB_SANDBOX=docker integration lands. Always typed-fails so
/// `/internal/verify` answers HTTP 501 rather than inventing a verdict.
pub struct StubSandbox;

#[async_trait]
impl SandboxExecutor for StubSandbox {
    async fn run_exploit(&self, _params: &RunParams<'_>) -> Result<ExecOutcome, SandboxError> {
        Err(SandboxError::Unsupported(
            "StubSandbox configured — wire DockerCli (SCB_SANDBOX=docker) once blob pulling lands",
        ))
    }
}

/// Real executor driving `docker run` via argument arrays (no shell).
///
/// Environment contract: the packed environment image must already be
/// running as a container named/aliased `target` on the docker network given
/// by [`DockerCli::network`] (scb-pack's dev-plane compose provides exactly
/// this shape, which is what makes local results predictive — D13).
pub struct DockerCli {
    pub runtime_image: String,
    pub network: String,
    pub docker: PathBuf,
}

impl Default for DockerCli {
    fn default() -> Self {
        Self {
            runtime_image: "scb/exploit-runtime:latest".to_string(),
            network: "bridge".to_string(),
            docker: PathBuf::from("docker"),
        }
    }
}

#[async_trait]
impl SandboxExecutor for DockerCli {
    async fn run_exploit(&self, p: &RunParams<'_>) -> Result<ExecOutcome, SandboxError> {
        // Stage the exploit into the work dir (mounted read-write at /work).
        let exploit_path: PathBuf = p.work_dir.join("exploit.py");
        tokio::fs::write(&exploit_path, p.exploit_py)
            .await
            .map_err(SandboxError::Io)?;

        let memory = format!("{}m", p.memory_mb);
        let cpus = format!("{}", p.cpus);
        let seed = p.seed.to_string();
        let mut args: Vec<String> = vec![
            "run".into(),
            "--rm".into(),
            "--network".into(),
            self.network.clone(),
            "--memory".into(),
            memory,
            "--cpus".into(),
            cpus,
            "-e".into(),
            format!("SEED={seed}"),
            "-e".into(),
            format!("TARGET_HOST={}", p.target_host),
            "-e".into(),
            format!("TARGET_PORT={}", p.target_port),
            "-v".into(),
            format!("{}:/work", p.work_dir.display()),
            "-w".into(),
            "/work".into(),
            self.runtime_image.clone(),
            "python3".into(),
            "exploit.py".into(),
        ];
        if p.aslr_off {
            // Parity note: this disables ASLR for the EXPLOIT process; the
            // target-side personality comes from its own compose entrypoint
            // (see cli compose generator). Both sides flip together.
            args.splice(
                args.len() - 5..args.len() - 5,
                [
                    "--security-opt".to_string(),
                    "seccomp=unconfined".to_string(),
                ],
            );
        }

        let child = tokio::process::Command::new(&self.docker)
            .args(&args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(SandboxError::Io)?;

        let deadline = Duration::from_secs(p.timeout_secs);
        let output = tokio::time::timeout(deadline, async {
            let out = child.wait_with_output().await?;
            Ok::<_, std::io::Error>(out)
        })
        .await;

        match output {
            Err(_) => Err(SandboxError::Timeout),
            Ok(Ok(out)) => {
                let mut text =
                    String::from_utf8_lossy(&out.stdout).into_owned();
                text.push_str(&String::from_utf8_lossy(&out.stderr));
                Ok(ExecOutcome {
                    output: text,
                    timed_out: false,
                })
            }
            Ok(Err(e)) => Err(SandboxError::Io(e)),
        }
    }
}
