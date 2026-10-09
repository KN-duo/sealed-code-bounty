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
use tokio::io::AsyncReadExt;

const MAX_CAPTURE_PER_STREAM: usize = 512 * 1024;

async fn drain_bounded<R: tokio::io::AsyncRead + Unpin>(mut stream: R) -> std::io::Result<Vec<u8>> {
    let mut kept = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        let remaining = MAX_CAPTURE_PER_STREAM.saturating_sub(kept.len());
        kept.extend_from_slice(&chunk[..n.min(remaining)]);
        // Continue draining after the cap so a noisy child cannot block on a
        // full pipe. The verdict examines only this bounded prefix.
    }
    Ok(kept)
}

#[derive(Debug, Clone)]
pub struct RunParams<'a> {
    /// Directory holding the unpacked environment rootfs copy (mounted ro).
    pub rootfs_dir: &'a Path,
    /// Private directory containing the safely unpacked exploit (/work ro).
    pub work_dir: &'a Path,
    /// Validated argument array, e.g. ["python3", "exploit.py"].
    pub exploit_entrypoint: &'a [String],
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
pub fn target_run_args(name: &str, image: &str, p: &RunParams<'_>, machine: &str) -> Vec<String> {
    let memory = format!("{}m", p.memory_mb);
    let cpus = format!("{}", p.cpus);
    let seed = p.seed.to_string();
    vec![
        "-d".into(),
        "--rm".into(),
        "--pull=never".into(),
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
pub fn exploit_run_args(p: &RunParams<'_>, machine: &str, runtime_image: &str) -> Vec<String> {
    let memory = format!("{}m", p.memory_mb);
    let cpus = format!("{}", p.cpus);
    let seed = p.seed.to_string();
    let mut tail = p.exploit_entrypoint.to_vec();
    if p.aslr_off {
        tail = ["setarch".into(), machine.into(), "-R".into()]
            .into_iter()
            .chain(tail)
            .collect();
    }
    let mut args: Vec<String> = vec![
        "--pull=never".into(),
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
        format!("{}:/work:ro", p.work_dir.display()),
        "-w".into(),
        "/work".into(),
    ];
    args.push(runtime_image.to_string());
    args.extend(tail);
    args
}

// ---------------------------------------------------------------------------
// Real executor driving `docker` via argument arrays only (no shell spawn).
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ContainerCli {
    pub executable: PathBuf,
    pub runtime_image: String,
    pub network: String,
    pub podman: bool,
    pub seccomp_profile: Option<PathBuf>,
    pub subuid_start: u32,
}

/// Compatibility name used by local Docker development and existing callers.
pub type DockerCli = ContainerCli;

impl Default for ContainerCli {
    fn default() -> Self {
        Self {
            executable: PathBuf::from("docker"),
            runtime_image: "scb/exploit-runtime:latest".to_string(),
            network: "scb-loopback".to_string(),
            podman: false,
            seccomp_profile: None,
            subuid_start: 100_000,
        }
    }
}

impl ContainerCli {
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

    pub fn podman_from_env() -> Result<Self, String> {
        let mut s = Self {
            executable: std::env::var_os("SCB_PODMAN_CLI")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("podman")),
            podman: true,
            seccomp_profile: Some(
                std::env::var_os("SCB_SECCOMP_PROFILE")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("/app/nitro/deny-vsock-seccomp.json")),
            ),
            subuid_start: std::env::var("SCB_PODMAN_SUBUID_START")
                .unwrap_or_else(|_| "100000".into())
                .parse()
                .map_err(|_| "SCB_PODMAN_SUBUID_START must be an integer")?,
            ..Self::default()
        };
        if let Ok(img) = std::env::var("SCB_RUNTIME_IMAGE") {
            s.runtime_image = img;
        }
        if let Ok(net) = std::env::var("SCB_NETWORK") {
            s.network = net;
        }
        Ok(s)
    }

    fn command(&self) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(&self.executable);
        if self.podman {
            cmd.args(["--storage-driver", "vfs"]);
        }
        cmd
    }

    async fn run_capture(
        &self,
        args: &[String],
        timeout: Duration,
    ) -> Result<std::process::Output, SandboxError> {
        let mut cmd = self.command();
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
        let _ = self.command().args(["rm", "-f", name]).output().await;
    }
}

#[async_trait]
impl SandboxExecutor for ContainerCli {
    async fn run_exploit(&self, p: &RunParams<'_>) -> Result<ExecOutcome, SandboxError> {
        use rand::RngCore;
        let uniq = format!("{:016x}", rand::rngs::OsRng.next_u64());
        let target_name = format!("scb-target-{uniq}");
        let exploit_name = format!("scb-exploit-{uniq}");
        let machine = machine_of("amd64"); // Nitro EIFs are built for x86_64.

        // 1. Create a per-verification internal network so concurrent requests
        // cannot discover or connect to another challenge's target.
        let network = format!("{}-{uniq}", self.network);
        let mut run = p.clone();
        run.target_network = network.clone();
        // Cleanup closure used on every exit path once containers may exist.
        async fn cleanup(cli: &DockerCli, exploit: &str, target: &str) {
            cli.rm_force(exploit).await;
            cli.rm_force(target).await;
        }

        async fn cleanup_network(cli: &DockerCli, network: &str) {
            let _ = cli
                .command()
                .args(["network", "rm", network])
                .output()
                .await;
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
                    .find_map(|l| {
                        l.strip_prefix("Loaded image: ")
                            .or_else(|| l.strip_prefix("Loaded image(s): "))
                            .map(str::to_string)
                    })
                    .ok_or_else(|| {
                        SandboxError::Runtime("docker load did not report an image ref".into())
                    })?
            }
            (None, Some(img)) => img.clone(),
            (None, None) => {
                return Err(SandboxError::Runtime(
                    "no target image: supply env_blob_path or target_image".into(),
                ))
            }
        };

        if self.podman {
            self.chown_for_user_namespace(p.rootfs_dir).await?;
            self.chown_for_user_namespace(p.work_dir).await?;
        }
        let net = net_create_args(&network);
        let network_out = self.run_capture(&net, Duration::from_secs(15)).await?;
        if !network_out.status.success() {
            return Err(SandboxError::Runtime(
                "could not create isolated challenge network".into(),
            ));
        }

        // 3. Start target detached.
        let mut t_args: Vec<String> = vec!["run".to_string()];
        if self.podman {
            t_args.extend(self.podman_hardening(false, false));
        }
        t_args.extend(target_run_args(&target_name, &target_image, &run, machine));
        let target_out = match self.run_capture(&t_args, Duration::from_secs(60)).await {
            Ok(out) => out,
            Err(e) => {
                cleanup(self, &exploit_name, &target_name).await;
                cleanup_network(self, &network).await;
                return Err(e);
            }
        };
        if !target_out.status.success() {
            cleanup(self, &exploit_name, &target_name).await;
            cleanup_network(self, &network).await;
            return Err(SandboxError::Runtime(
                "could not start challenge target".into(),
            ));
        }

        // 4. Exploit container with hard wall-clock timeout. kill_on_drop is
        //    the belt; explicit start_kill+reap below is the suspenders
        //    (audit P1-2: timed-out runs must not leak containers).
        let mut exploit_args = Vec::new();
        if self.podman {
            exploit_args.extend(self.podman_hardening(true, true));
        }
        exploit_args.extend(exploit_run_args(&run, machine, &self.runtime_image));
        let mut cmd = self.command();
        cmd.arg("run")
            .arg("--name")
            .arg(&exploit_name)
            .args(&exploit_args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                cleanup(self, &exploit_name, &target_name).await;
                cleanup_network(self, &network).await;
                return Err(SandboxError::Io(e));
            }
        };
        let Some(stdout) = child.stdout.take() else {
            let _ = child.start_kill();
            cleanup(self, &exploit_name, &target_name).await;
            cleanup_network(self, &network).await;
            return Err(SandboxError::Runtime("exploit stdout pipe missing".into()));
        };
        let Some(stderr) = child.stderr.take() else {
            let _ = child.start_kill();
            cleanup(self, &exploit_name, &target_name).await;
            cleanup_network(self, &network).await;
            return Err(SandboxError::Runtime("exploit stderr pipe missing".into()));
        };
        let stdout_task = tokio::spawn(drain_bounded(stdout));
        let stderr_task = tokio::spawn(drain_bounded(stderr));
        let _status =
            match tokio::time::timeout(Duration::from_secs(p.timeout_secs), child.wait()).await {
                Err(_) => {
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                    stdout_task.abort();
                    stderr_task.abort();
                    cleanup(self, &exploit_name, &target_name).await;
                    cleanup_network(self, &network).await;
                    return Err(SandboxError::Timeout);
                }
                Ok(Err(error)) => {
                    stdout_task.abort();
                    stderr_task.abort();
                    cleanup(self, &exploit_name, &target_name).await;
                    cleanup_network(self, &network).await;
                    return Err(SandboxError::Io(error));
                }
                Ok(Ok(status)) => status,
            };
        let stdout = stdout_task.await;
        let stderr = stderr_task.await;
        cleanup(self, &exploit_name, &target_name).await;
        cleanup_network(self, &network).await;
        let stdout = stdout
            .map_err(|_| SandboxError::Runtime("exploit stdout collection failed".into()))?
            .map_err(SandboxError::Io)?;
        let stderr = stderr
            .map_err(|_| SandboxError::Runtime("exploit stderr collection failed".into()))?
            .map_err(SandboxError::Io)?;
        let mut text = String::from_utf8_lossy(&stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&stderr));
        Ok(ExecOutcome {
            output: text,
            timed_out: false,
        })
    }
}

impl ContainerCli {
    fn podman_hardening(&self, read_only: bool, no_new_privs: bool) -> Vec<String> {
        let mut args = vec![
            "--cap-drop=all".into(),
            format!("--uidmap=0:{}:65536", self.subuid_start),
            format!("--gidmap=0:{}:65536", self.subuid_start),
            "--pids-limit=64".into(),
        ];
        if no_new_privs {
            args.push("--security-opt=no-new-privileges".into());
        }
        if let Some(profile) = &self.seccomp_profile {
            args.push("--security-opt".into());
            args.push(format!("seccomp={}", profile.display()));
        }
        if read_only {
            args.push("--read-only".into());
            args.push("--tmpfs".into());
            args.push("/tmp:rw,nosuid,nodev,size=16m".into());
        }
        args
    }

    async fn chown_for_user_namespace(&self, path: &Path) -> Result<(), SandboxError> {
        let owner = format!("{}:{}", self.subuid_start, self.subuid_start);
        let output = tokio::process::Command::new("chown")
            .arg("-R")
            .arg("--no-dereference")
            .arg(owner)
            .arg(path)
            .output()
            .await
            .map_err(SandboxError::Io)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(SandboxError::Runtime(
                "could not map the private run workspace into the sandbox".into(),
            ))
        }
    }
}

#[cfg(test)]
mod output_tests {
    use super::{drain_bounded, MAX_CAPTURE_PER_STREAM};
    use tokio::io::{duplex, AsyncWriteExt};

    #[tokio::test]
    async fn noisy_exploit_output_is_drained_but_memory_bounded() {
        let (mut writer, reader) = duplex(8192);
        let sender = tokio::spawn(async move {
            let chunk = vec![b'A'; 8192];
            for _ in 0..((MAX_CAPTURE_PER_STREAM / chunk.len()) + 4) {
                writer.write_all(&chunk).await.unwrap();
            }
            writer.shutdown().await.unwrap();
        });
        let output = drain_bounded(reader).await.unwrap();
        sender.await.unwrap();
        assert_eq!(output.len(), MAX_CAPTURE_PER_STREAM);
        assert!(output.iter().all(|b| *b == b'A'));
    }
}
