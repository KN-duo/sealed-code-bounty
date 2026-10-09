//! Safe unpacking of environment tarballs and sealed exploit ZIPs (§4.3 step 2).
//!
//! Hard rules, enforced structurally:
//!  * total uncompressed size ≤ `max_total_bytes` (zip-bomb defense)
//!  * at most `max_files` entries
//!  * absolute paths and `..` components rejected (traversal)
//!  * ALL symlinks and hardlinks rejected — a rootfs for a single-run
//!    verification has no legitimate need for them, and they are the classic
//!    escape vector out of the staging directory
//!  * only regular files and directories are extracted

use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone)]
pub struct UnpackLimits {
    pub max_total_bytes: u64,
    pub max_files: usize,
}

impl Default for UnpackLimits {
    fn default() -> Self {
        Self {
            max_total_bytes: 2 * 1024 * 1024 * 1024, // 2 GiB
            max_files: 10_000,
        }
    }
}

#[derive(Debug)]
pub enum UnpackError {
    Io(std::io::Error),
    Traversal(String),
    LinkRejected(String),
    UnsupportedEntryType(String),
    TooManyFiles { limit: usize },
    TotalSizeExceeded { limit: u64 },
    CompressedSizeExceeded { limit: usize },
    PathTooLong { limit: usize },
    DuplicatePath(String),
    InvalidArchive(String),
    InvalidEntrypoint(String),
    MissingEntrypoint,
}

impl std::fmt::Display for UnpackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnpackError::Io(e) => write!(f, "unpack io error: {e}"),
            UnpackError::Traversal(p) => write!(f, "path traversal rejected: {p}"),
            UnpackError::LinkRejected(p) => write!(f, "symlink/hardlink rejected: {p}"),
            UnpackError::UnsupportedEntryType(p) => {
                write!(f, "unsupported entry type (device/fifo/etc): {p}")
            }
            UnpackError::TooManyFiles { limit } => write!(f, "too many files (limit {limit})"),
            UnpackError::TotalSizeExceeded { limit } => {
                write!(
                    f,
                    "total uncompressed size exceeds {limit} bytes (zip bomb?)"
                )
            }
            UnpackError::CompressedSizeExceeded { limit } => {
                write!(f, "compressed exploit exceeds {limit} bytes")
            }
            UnpackError::PathTooLong { limit } => {
                write!(f, "archive path exceeds {limit} bytes")
            }
            UnpackError::DuplicatePath(p) => write!(f, "duplicate archive path: {p}"),
            UnpackError::InvalidArchive(e) => write!(f, "invalid exploit archive: {e}"),
            UnpackError::InvalidEntrypoint(e) => write!(f, "invalid exploit entrypoint: {e}"),
            UnpackError::MissingEntrypoint => {
                write!(f, "archive must contain exploit.py or scb-exploit.json")
            }
        }
    }
}

impl From<std::io::Error> for UnpackError {
    fn from(e: std::io::Error) -> Self {
        UnpackError::Io(e)
    }
}

#[derive(Debug, Clone)]
pub struct ExploitZipLimits {
    pub max_compressed_bytes: usize,
    pub max_total_bytes: u64,
    pub max_files: usize,
    pub max_path_bytes: usize,
    pub max_config_bytes: usize,
    pub max_command_args: usize,
    pub max_command_arg_bytes: usize,
}

impl Default for ExploitZipLimits {
    fn default() -> Self {
        Self {
            max_compressed_bytes: 9_000,
            max_total_bytes: 2 * 1024 * 1024,
            max_files: 128,
            max_path_bytes: 240,
            max_config_bytes: 4 * 1024,
            max_command_args: 16,
            max_command_arg_bytes: 256,
        }
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExploitConfig {
    format_version: u32,
    entrypoint: Vec<String>,
}

#[derive(Debug)]
pub struct UnpackedExploit {
    /// Argument vector used directly by DockerCli. The executable is fixed to
    /// python3; archives cannot provide a shell command string.
    pub entrypoint: Vec<String>,
    pub files: usize,
    pub total_bytes: u64,
}

/// A private temporary directory whose extracted plaintext files are
/// overwritten best-effort and whose directory is removed on every Drop path.
pub struct ExploitWorkspace {
    inner: tempfile::TempDir,
    plaintext_files: Vec<PathBuf>,
    zeroize_cap: u64,
}

impl ExploitWorkspace {
    pub fn new(parent: &Path, zeroize_cap: u64) -> Result<Self, UnpackError> {
        let inner = tempfile::Builder::new()
            .prefix("scb-exploit-")
            .tempdir_in(parent)?;
        Ok(Self {
            inner,
            plaintext_files: Vec::new(),
            zeroize_cap,
        })
    }

    pub fn path(&self) -> &Path {
        self.inner.path()
    }

    pub fn unpack_zip(
        &mut self,
        bytes: &[u8],
        limits: &ExploitZipLimits,
    ) -> Result<UnpackedExploit, UnpackError> {
        if bytes.len() > limits.max_compressed_bytes {
            return Err(UnpackError::CompressedSizeExceeded {
                limit: limits.max_compressed_bytes,
            });
        }

        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
            .map_err(|e| UnpackError::InvalidArchive(e.to_string()))?;
        // The ZIP reader stores names in a map and can collapse duplicate
        // central-directory names. Inspect the raw directory first so an
        // ambiguous archive is rejected instead of inheriting that policy.
        preflight_zip_directory(bytes, archive.central_directory_start(), limits)?;

        let mut seen = HashSet::new();
        let mut extracted_files = HashSet::new();
        let mut config_bytes = None;
        let mut total = 0u64;
        let mut file_count = 0usize;

        for index in 0..archive.len() {
            let mut entry = archive
                .by_index(index)
                .map_err(|e| UnpackError::InvalidArchive(e.to_string()))?;
            let raw_name = std::str::from_utf8(entry.name_raw())
                .map_err(|_| UnpackError::InvalidArchive("non-UTF-8 path".into()))?;
            let is_dir = entry.is_dir();
            let rel = safe_zip_relative(raw_name, is_dir, limits.max_path_bytes)?;
            if !seen.insert(rel.clone()) {
                return Err(UnpackError::DuplicatePath(rel.display().to_string()));
            }

            let mode_type = entry.unix_mode().unwrap_or(0) & 0o170000;
            if mode_type == 0o120000 {
                return Err(UnpackError::LinkRejected(raw_name.to_string()));
            }
            if is_dir {
                if mode_type != 0 && mode_type != 0o040000 {
                    return Err(UnpackError::UnsupportedEntryType(raw_name.to_string()));
                }
                std::fs::create_dir_all(self.path().join(&rel))?;
                continue;
            }
            if mode_type != 0 && mode_type != 0o100000 {
                return Err(UnpackError::UnsupportedEntryType(raw_name.to_string()));
            }

            file_count += 1;
            if file_count > limits.max_files {
                return Err(UnpackError::TooManyFiles {
                    limit: limits.max_files,
                });
            }
            let declared_size = entry.size();
            total = total
                .checked_add(declared_size)
                .ok_or(UnpackError::TotalSizeExceeded {
                    limit: limits.max_total_bytes,
                })?;
            if total > limits.max_total_bytes {
                return Err(UnpackError::TotalSizeExceeded {
                    limit: limits.max_total_bytes,
                });
            }
            if rel == Path::new("scb-exploit.json")
                && declared_size > limits.max_config_bytes as u64
            {
                return Err(UnpackError::InvalidEntrypoint(
                    "scb-exploit.json exceeds the config size limit".into(),
                ));
            }

            let target = self.path().join(&rel);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)?;
            self.plaintext_files.push(rel.clone());

            let mut config = (rel == Path::new("scb-exploit.json"))
                .then(|| Vec::with_capacity(declared_size as usize));
            let mut copied = 0u64;
            let mut buffer = [0u8; 16 * 1024];
            loop {
                let count = entry.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                copied =
                    copied
                        .checked_add(count as u64)
                        .ok_or(UnpackError::TotalSizeExceeded {
                            limit: limits.max_total_bytes,
                        })?;
                if copied > declared_size || copied > limits.max_total_bytes {
                    return Err(UnpackError::InvalidArchive(
                        "entry expanded beyond its declared size".into(),
                    ));
                }
                out.write_all(&buffer[..count])?;
                if let Some(config) = &mut config {
                    config.extend_from_slice(&buffer[..count]);
                }
            }
            if copied != declared_size {
                return Err(UnpackError::InvalidArchive(
                    "entry size did not match its central directory record".into(),
                ));
            }
            out.sync_all()?;
            drop(out);
            extracted_files.insert(rel.clone());
            if config.is_some() {
                config_bytes = config;
            }
        }

        let has_default = extracted_files.contains(Path::new("exploit.py"));
        let entrypoint = if let Some(bytes) = config_bytes {
            if has_default {
                return Err(UnpackError::InvalidEntrypoint(
                    "include either exploit.py or scb-exploit.json, not both".into(),
                ));
            }
            let config: ExploitConfig = serde_json::from_slice(&bytes)
                .map_err(|e| UnpackError::InvalidEntrypoint(e.to_string()))?;
            if config.format_version != 1 {
                return Err(UnpackError::InvalidEntrypoint(
                    "format_version must be 1".into(),
                ));
            }
            validate_exploit_entrypoint(&config.entrypoint, &extracted_files, limits)?
        } else if has_default {
            vec!["python3".into(), "exploit.py".into()]
        } else {
            return Err(UnpackError::MissingEntrypoint);
        };

        Ok(UnpackedExploit {
            entrypoint,
            files: file_count,
            total_bytes: total,
        })
    }
}

fn preflight_zip_directory(
    bytes: &[u8],
    start: u64,
    limits: &ExploitZipLimits,
) -> Result<(), UnpackError> {
    const CENTRAL: &[u8; 4] = b"PK\x01\x02";
    const EOCD: &[u8; 4] = b"PK\x05\x06";
    const ZIP64_EOCD: &[u8; 4] = b"PK\x06\x06";
    const FIXED_LEN: usize = 46;

    let mut offset = usize::try_from(start)
        .map_err(|_| UnpackError::InvalidArchive("central directory offset overflow".into()))?;
    let mut count = 0usize;
    let mut paths = HashSet::new();
    loop {
        let signature = bytes
            .get(offset..offset.saturating_add(4))
            .ok_or_else(|| UnpackError::InvalidArchive("truncated central directory".into()))?;
        if signature == EOCD || signature == ZIP64_EOCD {
            return Ok(());
        }
        if signature != CENTRAL {
            return Err(UnpackError::InvalidArchive(
                "unexpected central directory record".into(),
            ));
        }
        let fixed_end = offset
            .checked_add(FIXED_LEN)
            .ok_or_else(|| UnpackError::InvalidArchive("central directory overflow".into()))?;
        let fixed = bytes.get(offset..fixed_end).ok_or_else(|| {
            UnpackError::InvalidArchive("truncated central directory entry".into())
        })?;
        let name_len = u16::from_le_bytes([fixed[28], fixed[29]]) as usize;
        let extra_len = u16::from_le_bytes([fixed[30], fixed[31]]) as usize;
        let comment_len = u16::from_le_bytes([fixed[32], fixed[33]]) as usize;
        let name_end = fixed_end
            .checked_add(name_len)
            .ok_or_else(|| UnpackError::InvalidArchive("central path length overflow".into()))?;
        let record_end = name_end
            .checked_add(extra_len)
            .and_then(|v| v.checked_add(comment_len))
            .ok_or_else(|| UnpackError::InvalidArchive("central record length overflow".into()))?;
        let raw_name = bytes
            .get(fixed_end..name_end)
            .ok_or_else(|| UnpackError::InvalidArchive("truncated central path".into()))?;
        let name = std::str::from_utf8(raw_name)
            .map_err(|_| UnpackError::InvalidArchive("non-UTF-8 path".into()))?;
        let rel = safe_zip_relative(name, name.ends_with('/'), limits.max_path_bytes)?;
        if !paths.insert(rel.clone()) {
            return Err(UnpackError::DuplicatePath(rel.display().to_string()));
        }
        count += 1;
        if count > limits.max_files {
            return Err(UnpackError::TooManyFiles {
                limit: limits.max_files,
            });
        }
        if record_end > bytes.len() {
            return Err(UnpackError::InvalidArchive(
                "truncated central directory record".into(),
            ));
        }
        offset = record_end;
    }
}

impl Drop for ExploitWorkspace {
    fn drop(&mut self) {
        for rel in &self.plaintext_files {
            let path = self.path().join(rel);
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.file_type().is_file() || meta.len() > self.zeroize_cap {
                continue;
            }
            let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(&path) else {
                continue;
            };
            let mut remaining = meta.len();
            let zeros = [0u8; 8192];
            while remaining > 0 {
                let count =
                    usize::try_from(remaining.min(zeros.len() as u64)).unwrap_or(zeros.len());
                if file.write_all(&zeros[..count]).is_err() {
                    break;
                }
                remaining -= count as u64;
            }
            let _ = file.sync_all();
        }
        // TempDir's Drop removes the tree without following symlinks.
    }
}

fn safe_zip_relative(
    name: &str,
    is_dir: bool,
    max_path_bytes: usize,
) -> Result<PathBuf, UnpackError> {
    if name.len() > max_path_bytes {
        return Err(UnpackError::PathTooLong {
            limit: max_path_bytes,
        });
    }
    if name.is_empty()
        || name.contains('\\')
        || name.contains('\0')
        || name.starts_with('/')
        || name.contains(':')
    {
        return Err(UnpackError::Traversal(name.to_string()));
    }
    let without_slash = if is_dir {
        name.strip_suffix('/').unwrap_or(name)
    } else {
        name
    };
    let path = Path::new(without_slash);
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            _ => return Err(UnpackError::Traversal(name.to_string())),
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(UnpackError::Traversal(name.to_string()));
    }
    Ok(normalized)
}

fn validate_exploit_entrypoint(
    args: &[String],
    files: &HashSet<PathBuf>,
    limits: &ExploitZipLimits,
) -> Result<Vec<String>, UnpackError> {
    if args.len() < 2 || args.len() > limits.max_command_args {
        return Err(UnpackError::InvalidEntrypoint(
            "entrypoint must be a bounded argument array with a Python script".into(),
        ));
    }
    if args[0] != "python3" {
        return Err(UnpackError::InvalidEntrypoint(
            "entrypoint executable must be python3".into(),
        ));
    }
    for arg in args {
        if arg.is_empty() || arg.len() > limits.max_command_arg_bytes || arg.contains('\0') {
            return Err(UnpackError::InvalidEntrypoint(
                "entrypoint argument is empty or too long".into(),
            ));
        }
    }
    let script = Path::new(&args[1]);
    let safe_script = safe_zip_relative(&args[1], false, limits.max_path_bytes)
        .map_err(|_| UnpackError::InvalidEntrypoint("entrypoint script path is unsafe".into()))?;
    if script.extension().and_then(|ext| ext.to_str()) != Some("py")
        || !files.contains(&safe_script)
    {
        return Err(UnpackError::InvalidEntrypoint(
            "entrypoint must name an extracted .py file".into(),
        ));
    }
    Ok(args.to_vec())
}

/// Validates `rel` as a safe relative path inside `dest`.
fn safe_relative(rel: &Path) -> Result<PathBuf, UnpackError> {
    if rel.is_absolute() || rel.as_os_str().is_empty() {
        return Err(UnpackError::Traversal(rel.display().to_string()));
    }
    for comp in rel.components() {
        match comp {
            Component::Normal(_) => {}
            Component::CurDir => {}
            _ => return Err(UnpackError::Traversal(rel.display().to_string())),
        }
    }
    Ok(rel.to_path_buf())
}

/// Extracts a gzipped tar stream into `dest`, enforcing `limits` throughout.
/// Returns (files_extracted, total_uncompressed_bytes).
pub fn extract_gz_tar<R: Read>(
    reader: R,
    dest: &Path,
    limits: &UnpackLimits,
) -> Result<(usize, u64), UnpackError> {
    let gz = flate2::read::GzDecoder::new(reader);
    let mut archive = tar::Archive::new(gz);
    archive.set_preserve_permissions(false);
    archive.set_unpack_xattrs(false);

    let mut files = 0usize;
    let mut total: u64 = 0;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let header = entry.header();

        match header.entry_type() {
            tar::EntryType::Regular => {}
            tar::EntryType::Directory => {
                let rel = safe_relative(header.path()?.as_ref())?;
                std::fs::create_dir_all(dest.join(rel))?;
                continue;
            }
            tar::EntryType::Symlink | tar::EntryType::Link => {
                return Err(UnpackError::LinkRejected(
                    header.path()?.display().to_string(),
                ));
            }
            other => {
                return Err(UnpackError::UnsupportedEntryType(format!(
                    "{} ({other:?})",
                    header.path()?.display()
                )));
            }
        }

        let size = header.size()?;
        total += size;
        if total > limits.max_total_bytes {
            return Err(UnpackError::TotalSizeExceeded {
                limit: limits.max_total_bytes,
            });
        }

        files += 1;
        if files > limits.max_files {
            return Err(UnpackError::TooManyFiles {
                limit: limits.max_files,
            });
        }

        let rel = safe_relative(header.path()?.as_ref())?;
        let target = dest.join(&rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Stream to disk; per-entry size was already counted above.
        let mut out = std::fs::File::create(&target)?;
        std::io::copy(&mut entry, &mut out)?;
        out.sync_all().ok();
    }
    Ok((files, total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use std::io::{Cursor, Read, Write};
    use tar::Builder;
    use tempfile::TempDir;

    fn gz(build: impl FnOnce(&mut Builder<Vec<u8>>)) -> Vec<u8> {
        let inner: Vec<u8> = Vec::new();
        let mut b = Builder::new(inner);
        build(&mut b);
        let raw = b.into_inner().expect("tar into_inner");
        let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(&raw).unwrap();
        enc.finish().unwrap()
    }

    fn zip_files(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, bytes) in entries {
            archive
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            archive.write_all(bytes).unwrap();
        }
        archive.finish().unwrap().into_inner()
    }

    fn mark_first_zip_entry_as_symlink(mut archive: Vec<u8>) -> Vec<u8> {
        let central = archive
            .windows(4)
            .position(|window| window == b"PK\x01\x02")
            .expect("central directory entry");
        archive[central + 5] = 3; // Unix creator OS
        let mode = (0o120777u32 << 16).to_le_bytes();
        archive[central + 38..central + 42].copy_from_slice(&mode);
        archive
    }

    fn duplicate_second_zip_name(mut archive: Vec<u8>) -> Vec<u8> {
        let matches: Vec<usize> = archive
            .windows(4)
            .enumerate()
            .filter_map(|(i, window)| (window == b"b.py").then_some(i))
            .collect();
        assert_eq!(matches.len(), 2); // local header and central directory
        for i in matches {
            archive[i] = b'a';
        }
        archive
    }

    #[test]
    fn exploit_zip_default_entrypoint_extracts_and_zeroizes_then_removes() {
        let archive = zip_files(&[
            ("exploit.py", b"print('flag')"),
            ("helpers/payload.bin", b"payload"),
        ]);
        let parent = TempDir::new().unwrap();
        let mut workspace = ExploitWorkspace::new(parent.path(), 2 * 1024 * 1024).unwrap();
        let unpacked = workspace
            .unpack_zip(&archive, &ExploitZipLimits::default())
            .unwrap();
        assert_eq!(unpacked.entrypoint, ["python3", "exploit.py"]);
        assert_eq!(unpacked.files, 2);
        assert_eq!(unpacked.total_bytes, 20);
        let workspace_path = workspace.path().to_path_buf();
        let mut open_plaintext = std::fs::File::open(workspace.path().join("exploit.py")).unwrap();
        drop(workspace);
        let mut zeroized = Vec::new();
        open_plaintext.read_to_end(&mut zeroized).unwrap();
        assert_eq!(zeroized, vec![0; b"print('flag')".len()]);
        assert!(!workspace_path.exists());
    }

    #[test]
    fn exploit_zip_accepts_bounded_python_argv_config() {
        let config =
            br#"{"format_version":1,"entrypoint":["python3","src/run.py","--mode","fast"]}"#;
        let archive = zip_files(&[
            ("scb-exploit.json", config),
            ("src/run.py", b"print('flag')"),
        ]);
        let workspace_parent = TempDir::new().unwrap();
        let mut workspace =
            ExploitWorkspace::new(workspace_parent.path(), 2 * 1024 * 1024).unwrap();
        let unpacked = workspace
            .unpack_zip(&archive, &ExploitZipLimits::default())
            .unwrap();
        assert_eq!(
            unpacked.entrypoint,
            ["python3", "src/run.py", "--mode", "fast"]
        );
        assert_eq!(unpacked.files, 2);
    }

    #[test]
    fn exploit_zip_rejects_traversal_absolute_and_backslash_paths() {
        for name in ["../escape.py", "/absolute.py", "dir\\escape.py"] {
            let archive = zip_files(&[(name, b"print('bad')")]);
            let workspace_parent = TempDir::new().unwrap();
            let mut workspace =
                ExploitWorkspace::new(workspace_parent.path(), 2 * 1024 * 1024).unwrap();
            let err = workspace
                .unpack_zip(&archive, &ExploitZipLimits::default())
                .unwrap_err();
            assert!(matches!(err, UnpackError::Traversal(_)), "{name}: {err}");
        }
    }

    #[test]
    fn exploit_zip_rejects_symlink_entries() {
        let archive = mark_first_zip_entry_as_symlink(zip_files(&[("exploit.py", b"target")]));
        let workspace_parent = TempDir::new().unwrap();
        let mut workspace =
            ExploitWorkspace::new(workspace_parent.path(), 2 * 1024 * 1024).unwrap();
        let err = workspace
            .unpack_zip(&archive, &ExploitZipLimits::default())
            .unwrap_err();
        assert!(matches!(err, UnpackError::LinkRejected(_)), "{err}");
    }

    #[test]
    fn exploit_zip_enforces_expanded_compressed_file_and_path_caps() {
        let archive = zip_files(&[("exploit.py", &vec![b'x'; 4096])]);
        let parent = TempDir::new().unwrap();
        let mut workspace = ExploitWorkspace::new(parent.path(), 128).unwrap();
        let limits = ExploitZipLimits {
            max_total_bytes: 128,
            ..ExploitZipLimits::default()
        };
        assert!(matches!(
            workspace.unpack_zip(&archive, &limits),
            Err(UnpackError::TotalSizeExceeded { .. })
        ));

        let two_files = zip_files(&[("exploit.py", b"x"), ("helper.py", b"y")]);
        let limits = ExploitZipLimits {
            max_files: 1,
            ..ExploitZipLimits::default()
        };
        assert!(matches!(
            workspace.unpack_zip(&two_files, &limits),
            Err(UnpackError::TooManyFiles { .. })
        ));

        let limits = ExploitZipLimits {
            max_path_bytes: 8,
            ..ExploitZipLimits::default()
        };
        assert!(matches!(
            workspace.unpack_zip(&zip_files(&[("exploit.py", b"x")]), &limits),
            Err(UnpackError::PathTooLong { .. })
        ));

        let limits = ExploitZipLimits {
            max_compressed_bytes: 4,
            ..ExploitZipLimits::default()
        };
        assert!(matches!(
            workspace.unpack_zip(&zip_files(&[("exploit.py", b"x")]), &limits),
            Err(UnpackError::CompressedSizeExceeded { .. })
        ));
    }

    #[test]
    fn exploit_zip_rejects_duplicates_missing_and_untrusted_entrypoints() {
        let parent = TempDir::new().unwrap();
        let mut workspace = ExploitWorkspace::new(parent.path(), 2 * 1024 * 1024).unwrap();
        let duplicate = duplicate_second_zip_name(zip_files(&[("a.py", b"one"), ("b.py", b"two")]));
        let duplicate_error = workspace
            .unpack_zip(&duplicate, &ExploitZipLimits::default())
            .unwrap_err();
        assert!(
            matches!(
                &duplicate_error,
                UnpackError::DuplicatePath(_) | UnpackError::InvalidArchive(_)
            ),
            "{duplicate_error}"
        );
        let normalized_duplicate = zip_files(&[("dir//run.py", b"one"), ("dir/run.py", b"two")]);
        assert!(matches!(
            workspace.unpack_zip(&normalized_duplicate, &ExploitZipLimits::default()),
            Err(UnpackError::DuplicatePath(_))
        ));
        assert!(matches!(
            workspace.unpack_zip(
                &zip_files(&[("readme.txt", b"hello")]),
                &ExploitZipLimits::default()
            ),
            Err(UnpackError::MissingEntrypoint)
        ));

        for config in [
            br#"{"format_version":1,"entrypoint":"python3 -c 'bad'"}"#.as_slice(),
            br#"{"format_version":1,"entrypoint":["sh","-c","bad"]}"#.as_slice(),
            br#"{"format_version":1,"entrypoint":["python3","../escape.py"]}"#.as_slice(),
            br#"{"format_version":1,"entrypoint":["python3","run.py"],"command":"sh -c bad"}"#
                .as_slice(),
        ] {
            let archive = zip_files(&[("scb-exploit.json", config), ("run.py", b"pass")]);
            let config_parent = TempDir::new().unwrap();
            let mut config_workspace =
                ExploitWorkspace::new(config_parent.path(), 2 * 1024 * 1024).unwrap();
            assert!(matches!(
                config_workspace.unpack_zip(&archive, &ExploitZipLimits::default()),
                Err(UnpackError::InvalidEntrypoint(_))
            ));
        }
    }

    #[test]
    fn happy_path_extracts_regular_tree() {
        let blob = gz(|b: &mut Builder<Vec<u8>>| {
            let add = |b: &mut Builder<Vec<u8>>, name: &str, data: &[u8]| {
                let mut h = tar::Header::new_gnu();
                if data.is_empty() {
                    // directory-style entry
                    h.set_entry_type(tar::EntryType::Directory);
                    h.set_size(0);
                    h.set_mode(0o755);
                    h.set_cksum();
                } else {
                    h.set_size(data.len() as u64);
                    h.set_mode(0o644);
                    h.set_cksum();
                }
                b.append_data(&mut h, name, data).unwrap();
            };
            add(b, "etc/", b"");
            add(b, "etc/motd", b"welcome");
            add(b, "bin/service", b"\x7fELF-fake-binary");
        });

        let tmp = TempDir::new().unwrap();
        let (n, total) = extract_gz_tar(&blob[..], tmp.path(), &UnpackLimits::default()).unwrap();
        assert_eq!(n, 2);
        assert!(total >= 7 + 15);
        assert!(tmp.path().join("etc/motd").exists());
        assert!(tmp.path().join("bin/service").exists());
    }

    /// Crafts a raw ustar entry — bypasses tar::Builder's own path
    /// sanitation, exactly like a genuinely malicious archive would.
    fn raw_ustar_entry(name: &str, data: &[u8]) -> Vec<u8> {
        let mut hdr = [0u8; 512];
        let name_bytes = name.as_bytes();
        hdr[..name_bytes.len()].copy_from_slice(name_bytes);
        hdr[100..108].copy_from_slice(b"0000644\0");
        hdr[108..116].copy_from_slice(b"0000000\0");
        hdr[116..124].copy_from_slice(b"0000000\0");
        hdr[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
        hdr[136..148].copy_from_slice(b"00000000000\0");
        hdr[156] = b'0'; // regular file
        hdr[257..263].copy_from_slice(b"ustar\0");
        hdr[263..265].copy_from_slice(b"00");
        // Checksum is computed with the chksum field itself as ASCII spaces,
        // then written back as 6 octal digits + NUL + space.
        hdr[148..156].copy_from_slice(b"        ");
        let sum: u32 = hdr.iter().map(|&b| b as u32).sum();
        hdr[148..156].copy_from_slice(format!("{:06o}\0 ", sum).as_bytes());

        let mut out = Vec::new();
        out.extend_from_slice(&hdr);
        out.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
        out
    }

    #[test]
    fn traversal_paths_are_rejected() {
        let raw = {
            let mut blob = raw_ustar_entry("../../escaped.txt", b"evil");
            blob.extend_from_slice(&[0u8; 1024]); // archive terminator
            blob
        };
        let mut gzenc = GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gzenc.write_all(&raw).unwrap();
        let blob = gzenc.finish().unwrap();

        let tmp = TempDir::new().unwrap();
        let err = extract_gz_tar(&blob[..], tmp.path(), &UnpackLimits::default()).unwrap_err();
        assert!(matches!(err, UnpackError::Traversal(_)), "{err}");
        assert!(!tmp.path().parent().unwrap().join("escaped.txt").exists());
    }

    #[test]
    fn symlink_escape_is_rejected() {
        let blob = gz(|b: &mut Builder<Vec<u8>>| {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            h.set_mode(0o777);
            h.set_link_name(Path::new("/etc/shadow")).unwrap();
            let empty: &[u8] = &[];
            b.append_data(&mut h, "innocent-link", empty).unwrap();
        });
        let tmp = TempDir::new().unwrap();
        let err = extract_gz_tar(&blob[..], tmp.path(), &UnpackLimits::default()).unwrap_err();
        assert!(matches!(err, UnpackError::LinkRejected(_)), "{err}");
    }

    #[test]
    fn hardlink_is_rejected() {
        let blob = gz(|b| {
            let data: &[u8] = b"anchor";
            let mut h = tar::Header::new_gnu();
            h.set_size(6);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "anchor.txt", data).unwrap();

            let mut lh = tar::Header::new_gnu();
            lh.set_entry_type(tar::EntryType::Link);
            lh.set_size(0);
            lh.set_mode(0o644);
            lh.set_link_name(Path::new("anchor.txt")).unwrap();
            let empty: &[u8] = &[];
            b.append_data(&mut lh, "hard.txt", empty).unwrap();
        });
        let tmp = TempDir::new().unwrap();
        let err = extract_gz_tar(&blob[..], tmp.path(), &UnpackLimits::default()).unwrap_err();
        assert!(matches!(err, UnpackError::LinkRejected(_)), "{err}");
    }

    #[test]
    fn zip_bomb_ratio_hits_total_size_cap() {
        let big = vec![0u8; 3 * 1024 * 1024]; // compresses tiny, expands huge
        let blob = gz(|b: &mut Builder<Vec<u8>>| {
            let mut h = tar::Header::new_gnu();
            h.set_size(big.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "bomb.bin", &big[..]).unwrap();
        });
        let tmp = TempDir::new().unwrap();
        let limits = UnpackLimits {
            max_total_bytes: 1024 * 1024, // 1 MiB cap vs 3 MiB payload
            max_files: 100,
        };
        let err = extract_gz_tar(&blob[..], tmp.path(), &limits).unwrap_err();
        assert!(
            matches!(err, UnpackError::TotalSizeExceeded { .. }),
            "{err}"
        );
    }

    #[test]
    fn file_count_cap_triggers() {
        const COUNT: usize = 50;
        let blob = gz(|b: &mut Builder<Vec<u8>>| {
            for i in 0..COUNT {
                let data: &[u8] = b"x";
                let mut h = tar::Header::new_gnu();
                h.set_size(1);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, format!("f{i}.txt"), data).unwrap();
            }
        });
        let tmp = TempDir::new().unwrap();
        let limits = UnpackLimits {
            max_total_bytes: u64::MAX,
            max_files: 10,
        };
        let err = extract_gz_tar(&blob[..], tmp.path(), &limits).unwrap_err();
        assert!(matches!(err, UnpackError::TooManyFiles { .. }), "{err}");
    }
}
