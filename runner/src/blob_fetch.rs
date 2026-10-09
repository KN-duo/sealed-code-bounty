//! Development-only blob fetch with SHA-256 verification and size caps.
//!
//! Downloads a tarball from a local path or https URL, computing sha256
//! incrementally during the stream and enforcing the same size caps as
//! the unpack module. Production must use the fixed-key vsock artifact broker.

use std::io::{Read, Write};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use sha2::Digest as _;
use tempfile::NamedTempFile;
use tokio::io::AsyncReadExt as _;

#[derive(Debug)]
pub enum FetchError {
    Io(std::io::Error),
    HashMismatch { expected: String, got: String },
    TooLarge { limit: u64 },
    UnsupportedScheme(String),
    DownloadFailed,
    Timeout,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Io(e) => write!(f, "blob fetch io error: {e}"),
            FetchError::HashMismatch { expected, got } => {
                write!(f, "sha256 mismatch: expected {expected}, got {got}")
            }
            FetchError::TooLarge { limit } => write!(f, "blob exceeds {limit} byte cap"),
            FetchError::UnsupportedScheme(s) => write!(f, "unsupported scheme: {s}"),
            FetchError::DownloadFailed => write!(f, "HTTPS blob download failed"),
            FetchError::Timeout => write!(f, "HTTPS blob download timed out"),
        }
    }
}

/// Downloads or copies a blob to `dest`, enforcing `max_bytes` cap.
///
/// Data is staged in a unique temporary file and atomically renamed to `dest` ONLY
/// after the size cap holds and (when provided) `expected_sha256` matches —
/// so a mismatched or oversized blob never persists at the destination path.
/// Returns (bytes_written, sha256_hex).
pub async fn fetch_blob(
    source: &str,
    dest: &Path,
    max_bytes: u64,
    expected_sha256: Option<&str>,
) -> Result<(u64, String), FetchError> {
    if source.starts_with("https://") {
        fetch_https(source, dest, max_bytes, expected_sha256).await
    } else if source.starts_with("file://") || !source.contains("://") {
        let local = source.strip_prefix("file://").unwrap_or(source);
        fetch_local(Path::new(local), dest, max_bytes, expected_sha256)
    } else {
        let scheme = source.split("://").next().unwrap_or("?").to_string();
        Err(FetchError::UnsupportedScheme(scheme))
    }
}

/// Shared staging discipline: stream src→staged, verify cap + optional hash,
/// then atomically rename staged→dest. On any failure the staged file is removed.
fn stage_then_commit(
    mut input: impl Read,
    dest: &Path,
    max_bytes: u64,
    expected_sha256: Option<&str>,
) -> Result<(u64, String), FetchError> {
    let mut staged = create_staging(dest)?;
    let (total, hash) = stream_and_hash(&mut input, staged.as_file_mut(), max_bytes)?;
    commit_staging(staged, dest, total, hash, expected_sha256)
}

fn create_staging(dest: &Path) -> Result<NamedTempFile, FetchError> {
    let parent = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent).map_err(FetchError::Io)?;
    tempfile::Builder::new()
        .prefix(".scb-blob-")
        .tempfile_in(parent)
        .map_err(FetchError::Io)
}

fn commit_staging(
    staged: NamedTempFile,
    dest: &Path,
    total: u64,
    hash: String,
    expected_sha256: Option<&str>,
) -> Result<(u64, String), FetchError> {
    if let Some(expected) = expected_sha256 {
        if !hash.eq_ignore_ascii_case(expected) {
            return Err(FetchError::HashMismatch {
                expected: expected.to_owned(),
                got: hash,
            });
        }
    }
    staged.as_file().sync_all().map_err(FetchError::Io)?;
    staged.persist(dest).map_err(|e| FetchError::Io(e.error))?;
    Ok((total, hash))
}

/// Local file copy with incremental hash + size cap + staging.
fn fetch_local(
    src: &Path,
    dest: &Path,
    max_bytes: u64,
    expected_sha256: Option<&str>,
) -> Result<(u64, String), FetchError> {
    let input = std::fs::File::open(src).map_err(FetchError::Io)?;
    stage_then_commit(input, dest, max_bytes, expected_sha256)
}

/// HTTPS streaming download with incremental hash + size cap.
///
/// The developer supplies the URL. This is not a production egress boundary.
async fn fetch_https(
    url: &str,
    dest: &Path,
    max_bytes: u64,
    expected_sha256: Option<&str>,
) -> Result<(u64, String), FetchError> {
    fetch_https_with_command(
        tokio::process::Command::new("curl"),
        url,
        dest,
        max_bytes,
        expected_sha256,
        Duration::from_secs(35),
    )
    .await
}

async fn fetch_https_with_command(
    mut command: tokio::process::Command,
    url: &str,
    dest: &Path,
    max_bytes: u64,
    expected_sha256: Option<&str>,
    deadline: Duration,
) -> Result<(u64, String), FetchError> {
    let mut staged = create_staging(dest)?;
    // stdout goes directly into the already-open tempfile: curl never opens a
    // shared predictable pathname. Neither URL nor subprocess stderr is logged.
    let mut child = command
        .args([
            "--disable",
            "--fail",
            "--silent",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-redirs",
            "0",
            "--connect-timeout",
            "5",
            "--max-time",
            "30",
            "--max-filesize",
            &max_bytes.to_string(),
            "--url",
            url,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| FetchError::DownloadFailed)?;
    let mut stdout = child.stdout.take().ok_or(FetchError::DownloadFailed)?;
    let (total, hash) = tokio::time::timeout(deadline, async {
        let mut hash = sha2::Sha256::new();
        let mut buffer = [0u8; 65536];
        let mut total = 0u64;
        loop {
            let count = stdout
                .read(&mut buffer)
                .await
                .map_err(|_| FetchError::DownloadFailed)?;
            if count == 0 {
                break;
            }
            if count as u64 > max_bytes.saturating_sub(total) {
                return Err(FetchError::TooLarge { limit: max_bytes });
            }
            total += count as u64;
            hash.update(&buffer[..count]);
            staged.write_all(&buffer[..count]).map_err(FetchError::Io)?;
        }
        let status = child.wait().await.map_err(|_| FetchError::DownloadFailed)?;
        if !status.success() {
            return Err(match status.code() {
                Some(28) => FetchError::Timeout,
                Some(63) => FetchError::TooLarge { limit: max_bytes },
                _ => FetchError::DownloadFailed,
            });
        }
        Ok((total, hex::encode(hash.finalize())))
    })
    .await
    .map_err(|_| FetchError::Timeout)??;
    commit_staging(staged, dest, total, hash, expected_sha256)
}

/// Shared streaming helper: reads from `input`, writes to `output`,
/// enforces `max_bytes` total, returns (bytes_written, sha256_hex).
fn stream_and_hash<R: Read, W: std::io::Write>(
    input: &mut R,
    output: &mut W,
    max_bytes: u64,
) -> Result<(u64, String), FetchError> {
    let mut h = sha2::Sha256::new();
    let mut buf = [0u8; 65536];
    let mut total: u64 = 0;
    loop {
        let n = input.read(&mut buf).map_err(FetchError::Io)?;
        if n == 0 {
            break;
        }
        if n as u64 > max_bytes.saturating_sub(total) {
            return Err(FetchError::TooLarge { limit: max_bytes });
        }
        total += n as u64;
        h.update(&buf[..n]);
        output.write_all(&buf[..n]).map_err(FetchError::Io)?;
    }
    Ok((total, hex::encode(h.finalize())))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn fake_curl(script: &str) -> tokio::process::Command {
        let mut command = tokio::process::Command::new("sh");
        command.args(["-c", script, "curl"]);
        command
    }

    fn assert_no_staging(directory: &Path) {
        assert!(!std::fs::read_dir(directory).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".scb-blob-")
        }));
    }

    #[test]
    fn concurrent_destinations_with_same_stem_do_not_share_staging() {
        struct PausedReader<'a> {
            bytes: std::io::Cursor<Vec<u8>>,
            barrier: &'a std::sync::Barrier,
            started: bool,
        }
        impl Read for PausedReader<'_> {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                if !self.started {
                    self.started = true;
                    self.barrier.wait();
                }
                std::io::Read::read(&mut self.bytes, output)
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for (name, byte) in [("same.tar", 0xaa), ("same.zip", 0xbb)] {
                let dest = temp.path().join(name);
                let reader = PausedReader {
                    bytes: std::io::Cursor::new(vec![byte; 8192]),
                    barrier: &barrier,
                    started: false,
                };
                workers.push(scope.spawn(move || {
                    stage_then_commit(reader, &dest, 8192, None).unwrap();
                    assert_eq!(std::fs::read(dest).unwrap(), vec![byte; 8192]);
                }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        assert_no_staging(temp.path());
    }

    #[tokio::test]
    async fn https_stream_preserves_bytes_and_uses_bounded_curl_options() {
        let temp = tempfile::tempdir().unwrap();
        let dest = temp.path().join("out.tar.gz");
        let script = r#"
            test "$1" = --disable || exit 80
            case " $* " in *" --connect-timeout 5 "*) ;; *) exit 81;; esac
            case " $* " in *" --max-time 30 "*) ;; *) exit 82;; esac
            case " $* " in *" --proto =https "*) ;; *) exit 83;; esac
            case " $* " in *" --max-redirs 0 "*) ;; *) exit 84;; esac
            printf 'downloaded-tarball'
        "#;
        let expected = hex::encode(sha2::Sha256::digest(b"downloaded-tarball"));
        let (length, hash) = fetch_https_with_command(
            fake_curl(script),
            "https://unused.invalid/object",
            &dest,
            1024,
            Some(&expected),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(length, 18);
        assert_eq!(hash, expected);
        assert_eq!(std::fs::read(dest).unwrap(), b"downloaded-tarball");
        assert_no_staging(temp.path());
    }

    #[tokio::test]
    async fn https_failures_preserve_destination_and_remove_staging() {
        let temp = tempfile::tempdir().unwrap();
        let dest = temp.path().join("out.tar.gz");
        std::fs::write(&dest, b"previous-good-object").unwrap();
        let cases = [
            ("printf overflow", 1, None),
            ("printf data", 1024, Some("wrong-hash")),
            (
                "printf 'credential-in-url secret' >&2; printf data; exit 22",
                1024,
                None,
            ),
        ];
        for (script, max_bytes, hash) in cases {
            let error = fetch_https_with_command(
                fake_curl(script),
                "https://unused.invalid/?secret=credential",
                &dest,
                max_bytes,
                hash,
                Duration::from_secs(2),
            )
            .await
            .unwrap_err();
            assert!(!error.to_string().contains("secret"));
            assert!(!error.to_string().contains("credential"));
            assert_eq!(std::fs::read(&dest).unwrap(), b"previous-good-object");
            assert_no_staging(temp.path());
        }
    }

    #[tokio::test]
    async fn https_timeout_removes_staging() {
        let temp = tempfile::tempdir().unwrap();
        let dest = temp.path().join("out.tar.gz");
        let error = fetch_https_with_command(
            fake_curl("printf prefix; exec sleep 60"),
            "https://unused.invalid/object",
            &dest,
            1024,
            None,
            Duration::from_millis(30),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, FetchError::Timeout));
        assert!(!dest.exists());
        assert_no_staging(temp.path());
    }

    #[tokio::test]
    async fn curl_limit_exit_codes_remain_typed() {
        let temp = tempfile::tempdir().unwrap();
        let dest = temp.path().join("out.tar.gz");
        for (script, timeout) in [("exit 28", true), ("exit 63", false)] {
            let error = fetch_https_with_command(
                fake_curl(script),
                "https://unused.invalid/object",
                &dest,
                1024,
                None,
                Duration::from_secs(2),
            )
            .await
            .unwrap_err();
            if timeout {
                assert!(matches!(error, FetchError::Timeout));
            } else {
                assert!(matches!(error, FetchError::TooLarge { limit: 1024 }));
            }
            assert!(!dest.exists());
            assert_no_staging(temp.path());
        }
    }

    #[tokio::test]
    async fn cancelled_https_download_removes_staging() {
        let temp = tempfile::tempdir().unwrap();
        let dest = temp.path().join("out.tar.gz");
        let task_dest = dest.clone();
        let task = tokio::spawn(async move {
            fetch_https_with_command(
                fake_curl("printf prefix; exec sleep 60"),
                "https://unused.invalid/object",
                &task_dest,
                1024,
                None,
                Duration::from_secs(30),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while std::fs::read_dir(temp.path()).unwrap().next().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(!dest.exists());
        assert_no_staging(temp.path());
    }
}
