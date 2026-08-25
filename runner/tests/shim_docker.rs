//! DockerCli executor tests against the labeled docker shim
//! (`test-docker-shim/docker`). Proves argument arrays (network flags,
//! mounts, D13 setarch prefix, resource caps) and cleanup ORDER — including
//! that a timed-out exploit run still rm -f's both containers AFTER the kill.

use scb_runner::sandbox::{
    exploit_run_args, machine_of, net_create_args, target_run_args, DockerCli, RunParams,
    SandboxError, SandboxExecutor,
};
use std::path::PathBuf;
use std::sync::Mutex;

/// Process-global env (PATH/SCB_*) is mutated by the shim tests; serialize
/// them so parallel test threads cannot race the environ.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn shim_path() -> PathBuf {
    // tests/ -> runner/ -> test-docker-shim/docker
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("test-docker-shim");
    p.push("docker");
    p
}

fn params<'a>(
    rootfs: &'a std::path::Path,
    work: &'a std::path::Path,
    aslr_off: bool,
) -> RunParams<'a> {
    RunParams {
        rootfs_dir: rootfs,
        work_dir: work,
        exploit_py: b"print(open('/flag').read())",
        env_blob_path: None,
        target_image: Some("scb/target:test".into()),
        target_entrypoint: vec!["/usr/local/bin/serve".into()],
        target_host: "target".into(),
        target_network: "scb-loopback".into(),
        target_port: 1337,
        timeout_secs: 60,
        memory_mb: 512,
        cpus: 1.0,
        aslr_off,
        seed: 0,
    }
}

// ---------------------------------------------------------------------------
// Pure arg-builder coverage
// ---------------------------------------------------------------------------

#[test]
fn net_create_is_internal() {
    let a = net_create_args("scb-loopback");
    assert_eq!(a, vec!["network", "create", "--internal", "scb-loopback"]);
}

#[test]
fn exploit_args_carry_network_mounts_and_optional_setarch() {
    let rootfs = std::path::Path::new("/tmp/rf");
    let work = std::path::Path::new("/tmp/wk");

    let off = params(rootfs, work, true);
    let a = exploit_run_args(&off, "x86_64");
    let idx = |v: &str| a.iter().position(|x| x == v).expect(v);
    assert_eq!(a[idx("--network") + 1], "scb-loopback");
    assert!(a.iter().any(|x| x.ends_with("/srv:ro")));
    assert!(a.iter().any(|x| x.ends_with(":/work")));
    assert!(a.contains(&"SEED=0".to_string()));
    assert!(a.contains(&"TARGET_HOST=target".to_string()));
    assert!(a.contains(&"TARGET_PORT=1337".to_string()));

    // setarch sits directly before python3.
    let i = a.iter().position(|x| x == "setarch").expect("setarch");
    assert_eq!(&a[i..i + 4], &["setarch".to_string(), "x86_64".to_string(), "-R".to_string(), "python3".to_string()]);

    let on = params(rootfs, work, false);
    let a2 = exploit_run_args(&on, "x86_64");
    assert!(!a2.contains(&"setarch".to_string()));
    assert_eq!(
        a2.last().map(String::as_str),
        Some("exploit.py"),
        "python3 must be last without the wrapper"
    );
}

#[test]
fn target_args_carry_alias_internal_net_and_boot_script() {
    let rootfs = std::path::Path::new("/tmp/rf");
    let work = std::path::Path::new("/tmp/wk");
    let p = params(rootfs, work, true);
    let a = target_run_args("scb-target-x", "scb/target:test", &p, "x86_64");
    assert!(a.contains(&"-d".to_string()));
    let iname = a.iter().position(|x| x == "--name").unwrap();
    assert_eq!(a[iname + 1], "scb-target-x");
    let npos = a.iter().position(|x| x == "--network-alias").unwrap();
    assert_eq!(a[npos + 1], "target");
    assert!(a.contains(&"scb-loopback".to_string()));
    assert!(a.iter().any(|x| x.ends_with("/flag-src:ro")));

    // Boot script copies the injected flag over /flag and execs the manifest
    // entrypoint under setarch (single-quoted tokens; $(uname -m) unquoted).
    let boot = a.last().unwrap();
    assert!(boot.contains("cp /flag-src/flag /flag"));
    assert!(boot.contains("exec setarch x86_64 -R "), "boot={boot}");
    // Manifest tokens are single-quoted (injection-safe sh joining).
    assert!(boot.contains("'/usr/local/bin/serve'"));

    // aslr_on variant drops the wrapper entirely.
    let p_on = params(rootfs, work, false);
    let a_on = target_run_args("n", "img", &p_on, "x86_64");
    let boot_on = a_on.last().unwrap();
    assert!(!boot_on.contains("setarch"));
}

#[test]
fn machine_mapping_matches_docker_arches() {
    assert_eq!(machine_of("amd64"), "x86_64");
    assert_eq!(machine_of("arm64"), "aarch64");
}

// ---------------------------------------------------------------------------
// Shim-executed behaviour: arg arrays + timeout kill ordering
// ---------------------------------------------------------------------------

struct ShimEnv {
    prev_path: Option<std::ffi::OsString>,
}

impl Drop for ShimEnv {
    fn drop(&mut self) {
        if let Some(prev) = self.prev_path.take() {
            unsafe { std::env::set_var("PATH", prev) };
        }
    }
}

fn with_shim(tag: &str) -> (ShimEnv, PathBuf) {
    use rand::RngCore;
    let state = std::env::temp_dir().join(format!(
        "scb-shim-{tag}-{:016x}",
        rand::rngs::OsRng.next_u64()
    ));
    let state_clone = state.clone();
    std::fs::create_dir_all(&state).unwrap();

    let prev_path = std::env::var_os("PATH");
    unsafe {
        let mut newp = std::ffi::OsString::from(
            shim_path().parent().unwrap().to_string_lossy().to_string() + ":",
        );
        if let Some(p) = &prev_path {
            newp.push(p);
        }
        std::env::set_var("PATH", newp);
    }
    unsafe { std::env::set_var("SCB_SHIM_STATE", &state) };
    (
        ShimEnv { prev_path },
        state_clone,
    )
}

/// NOTE: PATH mutation is process-global; these tests therefore must not run
/// concurrently with other tests touching PATH. `cargo test` runs integration
/// tests in threads of one process — we accept the coupling here because the
/// two shim tests below are the only ones reading PATH. If that ever changes,
/// move them into a dedicated binary target.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // env mutation must span the whole run
async fn shim_happy_path_runs_exploit_and_returns_flag_line() {
    let _guard = ENV_LOCK.lock().unwrap();
    let (_env, state) = with_shim("happy");
    unsafe {
        std::env::set_var("SCB_SHIM_FLAG_OUT", "pwn{REAL_FLAG_FROM_TARGET}");
        std::env::remove_var("SCB_SHIM_EXPLOIT_SLEEP");
    }

    let rootfs = tempfile::TempDir::new().unwrap();
    let work = tempfile::TempDir::new().unwrap();
    let cli = DockerCli::default(); // resolves `docker` from the shimmed PATH

    let p = params(rootfs.path(), work.path(), true);
    let out = cli.run_exploit(&p).await.expect("shim run");
    assert!(
        out.output.contains("pwn{REAL_FLAG_FROM_TARGET}"),
        "output={:?} state_log={:?}",
        out.output,
        std::fs::read_to_string(state.join("cmd.log")).unwrap_or_default()
    );
    assert!(!out.timed_out);

    // Ordering proof: net-create -> load -> run-detached -> run-exploit ->
    // rm exploit -> rm target.
    let log = std::fs::read_to_string(state.join("cmd.log")).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    let find = |needle: &str| lines.iter().position(|l| l.contains(needle)).unwrap();
    let net = find("network-create");
    let detached = find("run-detached");
    let exploit = find("run-exploit");
    let rm_exploit = lines.iter().filter(|l| l.contains("rm scb-exploit")).count();
    let rm_target = lines.iter().filter(|l| l.contains("rm scb-target")).count();
    assert_eq!((rm_exploit, rm_target), (1, 1), "both containers cleaned once");
    assert!(net < detached && detached < exploit);
    assert!(exploit < find("rm scb-exploit"));
    void(rm_target);
    fn void<T>(_: T) {}
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // env mutation must span the whole run
async fn shim_timeout_kills_and_still_cleans_both_containers() {
    let _guard = ENV_LOCK.lock().unwrap();
    let (_env, state) = with_shim("timeout");
    unsafe {
        std::env::set_var("SCB_SHIM_EXPLOIT_SLEEP", "5"); // > 1s budget below
        std::env::remove_var("SCB_SHIM_FLAG_OUT");
    }

    let rootfs = tempfile::TempDir::new().unwrap();
    let work = tempfile::TempDir::new().unwrap();
    let cli = DockerCli::default();

    let mut p = params(rootfs.path(), work.path(), false);
    p.timeout_secs = 1;
    let err = match cli.run_exploit(&p).await {
        Err(SandboxError::Timeout) => None,
        Err(other) => Some(other.to_string()),
        Ok(_) => Some("expected Timeout".to_string()),
    };
    assert!(err.is_none(), "{err:?}");

    // Cleanup ordering after the kill: exploit removed before target, and
    // both AFTER the exploit run line.
    let log = std::fs::read_to_string(state.join("cmd.log")).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    let exploit_run = lines.iter().position(|l| l.contains("run-exploit")).unwrap();
    let rm_e = lines.iter().position(|l| l.contains("rm scb-exploit")).unwrap();
    let rm_t = lines.iter().position(|l| l.contains("rm scb-target")).unwrap();
    assert!(exploit_run < rm_e && rm_e < rm_t);
}
