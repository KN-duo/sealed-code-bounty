//! Streaming blob fetch with SHA-256 verification and size caps (Lane B).
//!
//! Downloads a tarball from a local path or https URL, computing sha256
//! incrementally during the stream and enforcing the same size caps as
//! the unpack module. Aborts on mismatch BEFORE persisting anything.

use std::io::Read;
use std::path::Path;

#[derive(Debug)]
pub enum FetchError {
    Io(std::io::Error),
    HashMismatch { expected: String, got: String },
    TooLarge { limit: u64 },
    UnsupportedScheme(String),
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
        }
    }
}

/// Downloads or copies a blob to `dest`, enforcing `max_bytes` cap.
///
/// Data is staged at `<dest>.part` and atomically renamed to `dest` ONLY
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
    let staged = dest.with_extension("part");
    // Ensure parent exists for both staged and final paths.
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(FetchError::Io)?;
    }
    let result = (|| {
        let mut output = std::fs::File::create(&staged).map_err(FetchError::Io)?;
        stream_and_hash(&mut input, &mut output, max_bytes)
    })();
    match result {
        Ok((total, hex)) => {
            if let Some(exp) = expected_sha256 {
                if !hex.eq_ignore_ascii_case(exp) {
                    let _ = std::fs::remove_file(&staged);
                    return Err(FetchError::HashMismatch {
                        expected: exp.to_string(),
                        got: hex,
                    });
                }
            }
            std::fs::rename(&staged, dest).map_err(FetchError::Io)?;
            Ok((total, hex))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&staged);
            Err(e)
        }
    }
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
/// REASONED vs EXECUTED: delegates the TLS fetch to `curl` (available on all
/// target systems; avoids an HTTP-client crate inside the enclave). The curl
/// invocation itself is not exercised in unit tests — tests cover the local
/// path, which shares `stage_then_commit`. In production the enclave's parent
/// proxies https per BUILD_PLAN §4.3.
async fn fetch_https(
    url: &str,
    dest: &Path,
    max_bytes: u64,
    expected_sha256: Option<&str>,
) -> Result<(u64, String), FetchError> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(FetchError::Io)?;
    }
    let tmp = dest.with_extension("part");
    let output = tokio::process::Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--max-filesize",
            &max_bytes.to_string(),
            "-o",
            tmp.to_str().unwrap_or("/dev/null"),
            url,
        ])
        .output()
        .await
        .map_err(|e| FetchError::Io(std::io::Error::other(e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let _ = std::fs::remove_file(&tmp);
        return Err(FetchError::Io(std::io::Error::other(format!(
            "curl failed: {stderr}"
        ))));
    }

    // Re-stage through stream_and_hash so cap/hash semantics match the local path.
    let input = std::fs::File::open(&tmp).map_err(FetchError::Io)?;
    let result = stage_then_commit(input, dest, max_bytes, expected_sha256);
    let _ = std::fs::remove_file(&tmp);
    result
}

/// Shared streaming helper: reads from `input`, writes to `output`,
/// enforces `max_bytes` total, returns (bytes_written, sha256_hex).
fn stream_and_hash<R: Read, W: std::io::Write>(
    input: &mut R,
    output: &mut W,
    max_bytes: u64,
) -> Result<(u64, String), FetchError> {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    let mut buf = [0u8; 65536];
    let mut total: u64 = 0;
    loop {
        let n = input.read(&mut buf).map_err(FetchError::Io)?;
        if n == 0 { break; }
        total += n as u64;
        if total > max_bytes { return Err(FetchError::TooLarge { limit: max_bytes }); }
        h.update(&buf[..n]);
        output.write_all(&buf[..n]).map_err(FetchError::Io)?;
    }
    Ok((total, hex::encode(h.finalize())))
}
