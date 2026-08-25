//! Sandbox execution boundary — REAL Docker implementation (Task 9).
//!
//! Reference attributions (studied before coding, per task spec):
//!  * kernelctf `server/server.py:172-183` — per-session TemporaryDirectory
//!    with a FRESH flag written per run, handed to the isolated runner,
//!    never reused across runs. Mirrored by our verify flow: the derived
//!    flag is injected into a private rootfs copy per verification.
//!  * kernelctf `server/qemu.sh:33-40` — read-only rootfs/flag drives plus
//!    hardening flags. Mirrored by mounting the unpacked rootfs READ-ONLY
//!    into the exploit container while the target boots from its own image.
//!  * kctf `challenge-templates/pwn/challenge/nsjail.cfg:17-23` (mode ONCE,
//!    rlimit_*: HARD) + `pwn/challenge/Dockerfile` CMD (socat + nsjail) —
//!    canonical "wrap the target process" pattern. DELIBERATE DEVIATION for
//!    v1: we rely on the container boundary (--network loopback-only
//!    fabric, --memory/--cpus, non-privileged) instead of nesting nsjail in
//!    arbitrary buyer images where no nsjail binary is guaranteed.
//!    Documented deviation; revisit on demand.

use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug)]
pub struct RunParams<'a> {
    /// Directory holding the unpacked environment rootfs copy (mounted ro).
    pub rootfs_dir: &'a Path,
    /// Work dir staged with the hunter's exploit at `exploit.py` (/work rw).
    pub work_dir: &'a Path,
    pub exploit_py: &'a [u8],
    /// Packed environment tarball (docker save | gzip) — loaded to
    /// materialise the target image.
    pub env_blob_path: Option<&'a Path>,
    /// Target image reference once loaded / manifest-provided.
    pub target_image: Option<String>,
    /// Original entrypoint+cmd tokens from the manifest (for D13 wrapping).
    pub target_entrypoint: Vec<String>,
    pub target_host: String,
    /// Loopback-only docker network shared by target + exploit containers.
    pub target_network: String,
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

/// Default until SCB_SANDBOX=docker is selected. Always typed-fails so
/// `/internal/verify` answers HTTP 501 rather than inventing a verdict.
pub struct StubSandbox;

#[async_trait]
impl SandboxExecutor for StubSandbox {
    async fn run_exploit(&self, _params: &RunParams<'_>) -> Result<ExecOutcome, SandboxError> {
        Err(SandboxError::Unsupported(
            "StubSandbox configured — set SCB_SANDBOX=docker for real execution",
        ))
    }
}

/// Machine name for the D13 setarch prefix, from a docker Architecture string.
pub fn machine_of(arch: &str) -> &str {
    match arch {
        "amd64" | "x86_64" => "x86_64",
        "arm64" | "aarch64" => "aarch64",
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Pure arg builders — unit-tested without any docker binary.
// ---------------------------------------------------------------------------

/// Minimal POSIX sh quoting for manifest-provided tokens.
fn shell_join(tokens: &[String]) -> String {
    tokens
        .iter()
        .map(|t| format!("'{}'", t.replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Boot script run as PID 1 inside the TARGET container: copies the runner's
/// injected flag over the image placeholder, then execs the original
/// entrypoint — wrapped in the D13 setarch personality when aslr_off.
/// The machine name is substituted by the caller from its known host arch.
fn target_boot_script(p: &RunParams<'_>, machine: &str) -> String {
    let base = if p.target_entrypoint.is_empty() {
        vec!["sleep".to_string(), "infinity".to_string()]
    } else {
        p.target_entrypoint.clone()
    };
    let joined = shell_join(&base);
    if p.aslr_off {
        format!("cp /flag-src/flag /flag 2>/dev/null || true; exec setarch {machine} -R {joined}")
    } else {
        format!("cp /flag-src/flag /flag 2>/dev/null || true; exec {joined}")
    }
}

/// `docker network create --internal <name>` — idempotent by caller.
pub fn net_create_args(network: &str) -> Vec<String> {
    vec![
        "network".to_string(),
        "create".to_string(),
        "--internal".to_string(),
        network.to_string(),
    ]
}

/// Detached target-container argv (everything after `docker run`).
pub fn target_run_args(
    name: &str,
    image: &str,
    p: &RunParams<'_>,
    machine: &str,
) -> Vec<String> {
    let memory = format!("{}m", p.memory_mb);
    let cpus = format!("{}", p.cpus);
    let seed = p.seed.to_string();
    vec![
        "-d".into(),
        "--rm".into(),
        "--name".into(),
        name.to_string(),
        "--network".into(),
        p.target_network.clone(),
        "--network-alias".into(),
        p.target_host.clone(),
        "--memory".into(),
        memory,
        "--cpus".into(),
        cpus,
        "-e".into(),
        format!("SEED={seed}"),
        "-v".into(),
        format!("{}:/flag-src:ro", p.rootfs_dir.display()),
        "--entrypoint".into(),
        "/bin/sh".into(),
        image.to_string(),
        "-c".into(),
        target_boot_script(p, machine),
    ]
}

/// Exploit-container argv (everything after `docker run`).
pub fn exploit_run_args(p: &RunParams<'_>, machine: &str) -> Vec<String> {
    let memory = format!("{}m", p.memory_mb);
    let cpus = format!("{}", p.cpus);
    let seed = p.seed.to_string();
    let mut tail: Vec<String> = vec!["python3".into(), "exploit.py".into()];
    if p.aslr_off {
        tail = ["setarch".into(), machine.into(), "-R".into()]
            .into_iter()
            .chain(tail)
            .collect();
    }
    let mut args: Vec<String> = vec![
        "--network".into(),
        p.target_network.clone(),
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
        format!("{}:/srv:ro", p.rootfs_dir.display()),
        "-v".into(),
        format!("{}:/work", p.work_dir.display()),
        "-w".into(),
        "/work".into(),
    ];
    args.extend(tail);
    args
}

// ---------------------------------------------------------------------------
// Real executor driving `docker` via argument arrays only (no shell spawn).
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DockerCli {
    pub docker: PathBuf,
    pub runtime_image: String,
    pub network: String,
}

impl Default for DockerCli {
    fn default() -> Self {
        Self {
            docker: PathBuf::from("docker"),
            runtime_image: "scb/exploit-runtime:latest".to_string(),
            network: "scb-loopback".to_string(),
        }
    }
}

impl DockerCli {
    pub fn from_env() -> Result<Self, String> {
        let mut s = Self::default();
        if let Ok(img) = std::env::var("SCB_RUNTIME_IMAGE") {
            s.runtime_image = img;
        }
        if let Ok(net) = std::env::var("SCB_NETWORK") {
            s.network = net;
        }
        Ok(s)
    }

    async fn run_capture(
        &self,
        args: &[String],
        timeout: Duration,
    ) -> Result<std::process::Output, SandboxError> {
        let mut cmd = tokio::process::Command::new(&self.docker);
        cmd.args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let child = cmd.spawn().map_err(SandboxError::Io)?;
        match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Err(_) => Err(SandboxError::Timeout),
            Ok(Err(e)) => Err(SandboxError::Io(e)),
            Ok(Ok(out)) => Ok(out),
        }
    }

    async fn rm_force(&self, name: &str) {
        let _ = tokio::process::Command::new(&self.docker)
            .args(["rm", "-f", name])
            .output()
            .await;
    }
}

#[async_trait]
impl SandboxExecutor for DockerCli {
    async fn run_exploit(&self, p: &RunParams<'_>) -> Result<ExecOutcome, SandboxError> {
        use rand::RngCore;
        let uniq = format!("{:016x}", rand::rngs::OsRng.next_u64());
        let target_name = format!("scb-target-{uniq}");
        let exploit_name = format!("scb-exploit-{uniq}");
        let machine = machine_of("amd64"); // host-arch assumption documented

        // Stage the hunter's exploit into the mounted work dir.
        tokio::fs::write(p.work_dir.join("exploit.py"), p.exploit_py)
            .await
            .map_err(SandboxError::Io)?;

        // 1. Loopback-only fabric (audit M3). Ignore "already exists".
        let net = net_create_args(&self.network);
        let _ = self.run_capture(&net, Duration::from_secs(15)).await;

        // Cleanup closure used on every exit path once containers may exist.
        async fn cleanup(cli: &DockerCli, exploit: &str, target: &str) {
            cli.rm_force(exploit).await;
            cli.rm_force(target).await;
        }

        // 2. Materialise the target image when a tarball is supplied.
        let target_image: String = match (p.env_blob_path, p.target_image.as_ref()) {
            (Some(blob), _) => {
                let load: Vec<String> =
                    vec!["load".into(), "-i".into(), blob.display().to_string()];
                let out = self.run_capture(&load, Duration::from_secs(600)).await?;
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                text.lines()
                    .find_map(|l| l.strip_prefix("Loaded image: ").map(str::to_string))
                    .ok_or_else(|| {
                        SandboxError::Runtime(
                            "docker load did not report an image ref".into(),
                        )
                    })?
            }
            (None, Some(img)) => img.clone(),
            (None, None) => {
                return Err(SandboxError::Runtime(
                    "no target image: supply env_blob_path or target_image".into(),
                ))
            }
        };

        // 3. Start target detached.
        let mut t_args: Vec<String> = vec!["run".to_string()];
        t_args.extend(target_run_args(&target_name, &target_image, p, machine));
        self.run_capture(&t_args, Duration::from_secs(60)).await?;

        // 4. Exploit container with hard wall-clock timeout. kill_on_drop is
        //    the belt; explicit start_kill+reap below is the suspenders
        //    (audit P1-2: timed-out runs must not leak containers).
        let e_args_full: Vec<String> = std::iter::once("run".to_string())
            .chain(exploit_run_args(p, machine))
            .collect();
        let mut cmd = tokio::process::Command::new(&self.docker);
        cmd.arg("run")
            .arg("--name")
            .arg(&exploit_name)
            .args(&e_args_full)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                cleanup(self, &exploit_name, &target_name).await;
                return Err(SandboxError::Io(e));
            }
        };

        let waited =
            tokio::time::timeout(Duration::from_secs(p.timeout_secs), child.wait()).await;

        let (timed_out, _status) = match waited {
            Err(_) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                cleanup(self, &exploit_name, &target_name).await;
                return Err(SandboxError::Timeout);
            }
            Ok(Ok(st)) => (false, Some(st)),
            Ok(Err(e)) => {
                cleanup(self, &exploit_name, &target_name).await;
                return Err(SandboxError::Io(e));
            }
        };

        let out = child.wait_with_output().await.ok();
        cleanup(self, &exploit_name, &target_name).await;

        if timed_out {
            return Err(SandboxError::Timeout);
        }
        let mut text = out
            .as_ref()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        if let Some(o) = &out {
            text.push_str(&String::from_utf8_lossy(&o.stderr));
        }
        Ok(ExecOutcome { output: text, timed_out })
    }
}
