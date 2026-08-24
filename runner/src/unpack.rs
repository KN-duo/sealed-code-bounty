//! Safe unpacking of the environment tarball (§4.3 step 2).
//!
//! Hard rules, enforced structurally:
//!  * total uncompressed size ≤ `max_total_bytes` (zip-bomb defense)
//!  * at most `max_files` entries
//!  * absolute paths and `..` components rejected (traversal)
//!  * ALL symlinks and hardlinks rejected — a rootfs for a single-run
//!    verification has no legitimate need for them, and they are the classic
//!    escape vector out of the staging directory
//!  * only regular files and directories are extracted

use std::io::Read;
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
                write!(f, "total uncompressed size exceeds {limit} bytes (zip bomb?)")
            }
        }
    }
}

impl From<std::io::Error> for UnpackError {
    fn from(e: std::io::Error) -> Self {
        UnpackError::Io(e)
    }
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
                return Err(UnpackError::LinkRejected(header.path()?.display().to_string()));
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
    use std::io::Write;
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
        let (n, total) =
            extract_gz_tar(&blob[..], tmp.path(), &UnpackLimits::default()).unwrap();
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
