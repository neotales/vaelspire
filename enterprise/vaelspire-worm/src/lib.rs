//! Copyright (c) Neotales. Proprietary — governed by `LICENSE-ENTERPRISE`.
//!
//! Tamper-evident hash-chained WORM (Write-Once Read-Many) [`AuditSink`] and
//! cloud immutable storage payload builders (S3 Object Lock, Azure Immutable Blob,
//! GCS Bucket Lock).

use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use vaelspire_core::extensions::AuditSink;
use vaelspire_core::{AuditEvent, AuthError, Timestamp};

/// Hex-encoded genesis hash anchoring sequence `0` of every WORM chain.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Cloud immutable object storage target for WORM archive export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectLockTarget {
    /// Amazon S3 / `MinIO` / Ceph RGW Object Lock (`COMPLIANCE` or `GOVERNANCE`).
    S3ObjectLock {
        /// Target bucket name.
        bucket: String,
        /// Key prefix (e.g. `"vaelspire/audit/"`).
        prefix: String,
        /// Whether to request `COMPLIANCE` (true) or `GOVERNANCE` (false) mode.
        compliance_mode: bool,
    },
    /// Azure Blob Storage Immutability Policy (time-based retention).
    AzureImmutableBlob {
        /// Storage container name.
        container: String,
        /// Blob prefix.
        prefix: String,
    },
    /// Google Cloud Storage Bucket Lock.
    GcsBucketLock {
        /// GCS bucket name.
        bucket: String,
        /// Object prefix.
        prefix: String,
    },
}

/// One cryptographically chained audit record inside a WORM batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainedAuditRecord {
    /// Monotonically increasing sequence number starting at `0`.
    pub sequence: u64,
    /// UTC epoch seconds when archived into the WORM chain.
    pub archived_at_unix: i64,
    /// Hash of the previous record (or [`GENESIS_HASH`] for `sequence == 0`).
    pub prev_hash: String,
    /// SHA-256 hex digest of `(sequence, archived_at_unix, prev_hash, canonical_event_json)`.
    pub entry_hash: String,
    /// Canonical JSON representation of the [`AuditEvent`].
    pub event_json: String,
}

/// Prepared immutable archive object ready for upload to S3/Azure/GCS with retention headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WormArchiveObject {
    /// Deterministic object key/path in the bucket or container.
    pub object_key: String,
    /// NDJSON body containing all chained records.
    pub body: Vec<u8>,
    /// Hex SHA-256 checksum of `body` for upload integrity verification.
    pub sha256_hex: String,
    /// Cloud-specific immutability/retention headers (e.g. `x-amz-object-lock-mode`).
    pub headers: Vec<(String, String)>,
}

/// Errors reported by [`verify_chain`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChainVerifyError {
    /// Sequence number skipped or out of order.
    #[error("sequence mismatch at index {index}: expected {expected}, got {actual}")]
    SequenceMismatch {
        /// Position in slice.
        index: usize,
        /// Expected sequence number.
        expected: u64,
        /// Observed sequence number.
        actual: u64,
    },
    /// `prev_hash` did not match the preceding record's `entry_hash`.
    #[error("broken previous-hash link at sequence {sequence}")]
    BrokenPrevHash {
        /// Sequence where linkage broke.
        sequence: u64,
    },
    /// Recomputed SHA-256 digest did not match `entry_hash` (tampering detected).
    #[error("entry digest mismatch at sequence {sequence}")]
    TamperedEntry {
        /// Sequence whose content failed verification.
        sequence: u64,
    },
}

/// Tamper-evident hash-chained [`AuditSink`] for Vaelspire Enterprise WORM compliance.
#[derive(Debug)]
pub struct WormAuditSink {
    retention_days: u32,
    records: Mutex<Vec<ChainedAuditRecord>>,
}

impl WormAuditSink {
    /// Create a new WORM audit sink with the configured retention window in days.
    #[must_use]
    pub const fn new(retention_days: u32) -> Self {
        Self {
            retention_days,
            records: Mutex::new(Vec::new()),
        }
    }

    /// Return a snapshot of all recorded chained audit entries.
    ///
    /// # Panics
    /// Never panics unless the internal mutex was poisoned.
    #[must_use]
    pub fn snapshot(&self) -> Vec<ChainedAuditRecord> {
        self.records
            .lock()
            .expect("worm audit mutex poisoned")
            .clone()
    }

    /// Package all recorded entries into a [`WormArchiveObject`] with cloud Object Lock headers.
    ///
    /// # Panics
    /// Never panics unless the internal mutex was poisoned.
    #[must_use]
    pub fn build_archive(
        &self,
        target: &ObjectLockTarget,
        retain_until_iso8601: &str,
    ) -> WormArchiveObject {
        let records = self.snapshot();
        let last_seq = records.last().map_or(0, |r| r.sequence);
        let mut ndjson = String::new();
        for rec in &records {
            if let Ok(line) = serde_json::to_string(rec) {
                ndjson.push_str(&line);
                ndjson.push('\n');
            }
        }
        let body = ndjson.into_bytes();
        let sha256_hex = hex_encode(&Sha256::digest(&body));

        let (prefix, headers) = match target {
            ObjectLockTarget::S3ObjectLock {
                prefix,
                compliance_mode,
                ..
            } => (
                prefix.as_str(),
                vec![
                    (
                        "x-amz-object-lock-mode".into(),
                        if *compliance_mode {
                            "COMPLIANCE".into()
                        } else {
                            "GOVERNANCE".into()
                        },
                    ),
                    (
                        "x-amz-object-lock-retain-until-date".into(),
                        retain_until_iso8601.into(),
                    ),
                    ("x-amz-content-sha256".into(), sha256_hex.clone()),
                ],
            ),
            ObjectLockTarget::AzureImmutableBlob { prefix, .. } => (
                prefix.as_str(),
                vec![
                    ("x-ms-immutability-policy-mode".into(), "Locked".into()),
                    (
                        "x-ms-immutability-policy-until-date".into(),
                        retain_until_iso8601.into(),
                    ),
                ],
            ),
            ObjectLockTarget::GcsBucketLock { prefix, .. } => (
                prefix.as_str(),
                vec![
                    (
                        "x-goog-meta-vaelspire-worm-sha256".into(),
                        sha256_hex.clone(),
                    ),
                    (
                        "x-goog-meta-vaelspire-retention-days".into(),
                        self.retention_days.to_string(),
                    ),
                ],
            ),
        };

        let clean_prefix = prefix.trim_end_matches('/');
        let object_key = format!(
            "{clean_prefix}/seq-{last_seq:012}-{}.ndjson",
            &sha256_hex[..12]
        );

        WormArchiveObject {
            object_key,
            body,
            sha256_hex,
            headers,
        }
    }
}

#[async_trait]
impl AuditSink for WormAuditSink {
    async fn emit(&self, event: &AuditEvent, now: Timestamp) -> Result<(), AuthError> {
        event.validate()?;
        let canonical = serde_json::json!({
            "id": event.id.to_string(),
            "tenant_id": event.tenant_id.map(|id| id.to_string()),
            "actor_id": event.actor_id.map(|id| id.to_string()),
            "action": event.action,
            "outcome": event.outcome,
            "fields": event.fields,
        });
        let event_json = serde_json::to_string(&canonical).map_err(|_| AuthError::Store)?;
        let archived_at_unix = now.unix_timestamp();
        let mut guard = self.records.lock().map_err(|_| AuthError::Store)?;
        let sequence = u64::try_from(guard.len()).map_err(|_| AuthError::Store)?;
        let prev_hash = guard
            .last()
            .map_or_else(|| GENESIS_HASH.to_owned(), |r| r.entry_hash.clone());
        let entry_hash = compute_entry_hash(sequence, archived_at_unix, &prev_hash, &event_json);
        guard.push(ChainedAuditRecord {
            sequence,
            archived_at_unix,
            prev_hash,
            entry_hash,
            event_json,
        });
        Ok(())
    }
}

/// Verify cryptographic hash-chain integrity across an ordered slice of WORM records.
///
/// # Errors
/// Returns [`ChainVerifyError`] at the first missing sequence, broken link, or tampered record.
pub fn verify_chain(records: &[ChainedAuditRecord]) -> Result<(), ChainVerifyError> {
    let mut expected_prev = GENESIS_HASH;
    for (index, record) in records.iter().enumerate() {
        let expected_seq = u64::try_from(index).unwrap_or(u64::MAX);
        if record.sequence != expected_seq {
            return Err(ChainVerifyError::SequenceMismatch {
                index,
                expected: expected_seq,
                actual: record.sequence,
            });
        }
        if record.prev_hash != expected_prev {
            return Err(ChainVerifyError::BrokenPrevHash {
                sequence: record.sequence,
            });
        }
        let recomputed = compute_entry_hash(
            record.sequence,
            record.archived_at_unix,
            &record.prev_hash,
            &record.event_json,
        );
        if recomputed != record.entry_hash {
            return Err(ChainVerifyError::TamperedEntry {
                sequence: record.sequence,
            });
        }
        expected_prev = &record.entry_hash;
    }
    Ok(())
}

fn compute_entry_hash(
    sequence: u64,
    archived_at_unix: i64,
    prev_hash: &str,
    event_json: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sequence.to_be_bytes());
    hasher.update(b"|");
    hasher.update(archived_at_unix.to_be_bytes());
    hasher.update(b"|");
    hasher.update(prev_hash.as_bytes());
    hasher.update(b"|");
    hasher.update(event_json.as_bytes());
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use vaelspire_core::Id;

    use super::*;

    fn sample_event(action: &str) -> AuditEvent {
        AuditEvent {
            id: Id::now_v7(),
            tenant_id: Some(Id::now_v7()),
            actor_id: Some(Id::now_v7()),
            action: action.into(),
            outcome: "ok".into(),
            fields: vec![("ip".into(), "203.0.113.10".into())],
        }
    }

    #[tokio::test]
    async fn hash_chain_verifies_and_detects_tampering() {
        let sink = WormAuditSink::new(2555);
        let now = Timestamp::from_unix_timestamp(1_750_000_000).expect("ts");
        sink.emit(&sample_event("auth.sign_in"), now)
            .await
            .expect("write 1");
        sink.emit(&sample_event("oidc.token.issued"), now)
            .await
            .expect("write 2");

        let mut chain = sink.snapshot();
        assert_eq!(chain.len(), 2);
        verify_chain(&chain).expect("valid chain");

        let archive = sink.build_archive(
            &ObjectLockTarget::S3ObjectLock {
                bucket: "vaelspire-audit".into(),
                prefix: "prod/audit".into(),
                compliance_mode: true,
            },
            "2033-11-26T00:00:00Z",
        );
        assert!(
            archive
                .object_key
                .starts_with("prod/audit/seq-000000000001-")
        );
        assert!(
            archive
                .headers
                .iter()
                .any(|(k, v)| k == "x-amz-object-lock-mode" && v == "COMPLIANCE")
        );

        // Tamper with record 0 and prove verify_chain catches it.
        chain[0].event_json.push(' ');
        assert_eq!(
            verify_chain(&chain),
            Err(ChainVerifyError::TamperedEntry { sequence: 0 })
        );
    }
}
