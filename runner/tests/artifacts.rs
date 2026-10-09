use async_trait::async_trait;
use scb_runner::artifacts::{fetch, ArtifactSource, Chunk, Kind, CHUNK_BYTES, ENVIRONMENT_CAP};
use scb_runner::submission_store::{receipt_for, StoreError};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Source {
    bytes: Vec<u8>,
    fault: &'static str,
    calls: AtomicUsize,
}
impl Source {
    fn new(bytes: Vec<u8>, fault: &'static str) -> Self {
        Self {
            bytes,
            fault,
            calls: AtomicUsize::new(0),
        }
    }
}
#[async_trait]
impl ArtifactSource for Source {
    async fn chunk(&self, _: Kind, _: &str, offset: u64) -> Result<Chunk, StoreError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.fault == "unavailable" {
            return Err(StoreError::Unavailable);
        }
        if self.fault == "pending" {
            std::future::pending::<()>().await;
        }
        let start = offset as usize;
        let mut bytes = self.bytes[start..(start + CHUNK_BYTES).min(self.bytes.len())].to_vec();
        if self.fault == "short" {
            bytes.pop();
        }
        let total_bytes = match self.fault {
            "oversize" => ENVIRONMENT_CAP + 1,
            "changing_total" if offset > 0 => self.bytes.len() as u64 + 1,
            _ => self.bytes.len() as u64,
        };
        Ok(Chunk {
            offset: if self.fault == "offset" {
                offset + 1
            } else {
                offset
            },
            total_bytes,
            bytes,
        })
    }
}

#[tokio::test]
async fn streams_multiple_chunks_and_deletes_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = vec![42; CHUNK_BYTES + 7];
    let hash = receipt_for(&bytes);
    let source = Source::new(bytes.clone(), "");
    let file = fetch(&source, Kind::Environment, &hash, dir.path())
        .await
        .unwrap();
    assert_eq!(std::fs::read(file.path()).unwrap(), bytes);
    assert_eq!(source.calls.load(Ordering::Relaxed), 2);
    drop(file);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn rejects_bad_parent_responses_without_persisting() {
    for fault in [
        "short",
        "offset",
        "oversize",
        "changing_total",
        "unavailable",
        "hash",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let source = Source::new(vec![42; CHUNK_BYTES + 7], fault);
        let hash = if fault == "hash" {
            "0".repeat(64)
        } else {
            receipt_for(&source.bytes)
        };
        assert!(
            fetch(&source, Kind::Environment, &hash, dir.path())
                .await
                .is_err(),
            "{fault}"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0, "{fault}");
    }
}

#[tokio::test]
async fn rejects_invalid_hash_and_manifest_cap() {
    let dir = tempfile::tempdir().unwrap();
    let source = Source::new(vec![42; 65537], "");
    assert!(matches!(
        fetch(&source, Kind::Manifest, "../path", dir.path()).await,
        Err(StoreError::InvalidReceipt)
    ));
    assert_eq!(source.calls.load(Ordering::Relaxed), 0);
    assert!(matches!(
        fetch(
            &source,
            Kind::Manifest,
            &receipt_for(&source.bytes),
            dir.path()
        )
        .await,
        Err(StoreError::TooLarge)
    ));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn cancellation_cleans_staged_file() {
    let dir = tempfile::tempdir().unwrap();
    let source = Source::new(vec![42], "pending");
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(20),
        fetch(
            &source,
            Kind::Environment,
            &receipt_for(&source.bytes),
            dir.path(),
        ),
    )
    .await;
    assert!(result.is_err());
    assert_eq!(source.calls.load(Ordering::Relaxed), 1);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
