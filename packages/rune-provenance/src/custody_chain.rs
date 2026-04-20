// ═══════════════════════════════════════════════════════════════════════
// Custody Chain — Layer 3 chain-of-custody recording.
//
// CustodyChainRecorder models possession transfers — who held an
// artifact when, and the cryptographic signature of each transfer.
// This is distinct from lineage (derivation relationships) because
// custody tracks physical/logical possession, not data flow.
//
// ContinuityEnforcingCustodyChainRecorder wraps any recorder and
// rejects transfers where from_custodian does not match the current
// holder, preventing gap-creating transfers.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::backend::{ArtifactRef, CustodianRef};
use crate::error::ProvenanceError;

// ── CustodyTransfer ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CustodyTransfer {
    pub transfer_id: String,
    pub artifact_ref: ArtifactRef,
    pub from_custodian: CustodianRef,
    pub to_custodian: CustodianRef,
    pub timestamp: i64,
    pub reason: String,
    pub signature_of_transfer: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

// ── CustodySnapshot ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CustodySnapshot {
    pub artifact_ref: ArtifactRef,
    pub current_custodian: CustodianRef,
    pub transfer_count: usize,
    pub first_transfer_at: Option<i64>,
    pub last_transfer_at: Option<i64>,
}

// ── CustodyChainRecorder trait ─────────────────────────────────────

pub trait CustodyChainRecorder {
    fn record_transfer(&mut self, transfer: CustodyTransfer) -> Result<(), ProvenanceError>;
    fn transfers_for_artifact(&self, artifact_ref: &ArtifactRef) -> Result<Vec<CustodyTransfer>, ProvenanceError>;
    fn current_custodian(&self, artifact_ref: &ArtifactRef) -> Result<Option<CustodianRef>, ProvenanceError>;
    fn custody_snapshot(&self, artifact_ref: &ArtifactRef) -> Result<Option<CustodySnapshot>, ProvenanceError>;
    fn transfer_count(&self) -> usize;
    fn recorder_id(&self) -> &str;
}

// ── InMemoryCustodyChainRecorder ───────────────────────────────────

pub struct InMemoryCustodyChainRecorder {
    id: String,
    transfers: Vec<CustodyTransfer>,
    // artifact → [indices into transfers]
    artifact_index: HashMap<String, Vec<usize>>,
}

impl InMemoryCustodyChainRecorder {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            transfers: Vec::new(),
            artifact_index: HashMap::new(),
        }
    }
}

impl CustodyChainRecorder for InMemoryCustodyChainRecorder {
    fn record_transfer(&mut self, transfer: CustodyTransfer) -> Result<(), ProvenanceError> {
        let idx = self.transfers.len();
        self.artifact_index
            .entry(transfer.artifact_ref.as_str().to_string())
            .or_default()
            .push(idx);
        self.transfers.push(transfer);
        Ok(())
    }

    fn transfers_for_artifact(&self, artifact_ref: &ArtifactRef) -> Result<Vec<CustodyTransfer>, ProvenanceError> {
        let indices = self.artifact_index.get(artifact_ref.as_str()).cloned().unwrap_or_default();
        let mut result: Vec<_> = indices.iter().map(|&i| self.transfers[i].clone()).collect();
        result.sort_by_key(|t| t.timestamp);
        Ok(result)
    }

    fn current_custodian(&self, artifact_ref: &ArtifactRef) -> Result<Option<CustodianRef>, ProvenanceError> {
        let transfers = self.transfers_for_artifact(artifact_ref)?;
        Ok(transfers.last().map(|t| t.to_custodian.clone()))
    }

    fn custody_snapshot(&self, artifact_ref: &ArtifactRef) -> Result<Option<CustodySnapshot>, ProvenanceError> {
        let transfers = self.transfers_for_artifact(artifact_ref)?;
        if transfers.is_empty() {
            return Ok(None);
        }
        Ok(Some(CustodySnapshot {
            artifact_ref: artifact_ref.clone(),
            current_custodian: transfers.last().unwrap().to_custodian.clone(),
            transfer_count: transfers.len(),
            first_transfer_at: transfers.first().map(|t| t.timestamp),
            last_transfer_at: transfers.last().map(|t| t.timestamp),
        }))
    }

    fn transfer_count(&self) -> usize {
        self.transfers.len()
    }

    fn recorder_id(&self) -> &str {
        &self.id
    }
}

// ── ContinuityEnforcingCustodyChainRecorder ────────────────────────

pub struct ContinuityEnforcingCustodyChainRecorder<R: CustodyChainRecorder> {
    inner: R,
}

impl<R: CustodyChainRecorder> ContinuityEnforcingCustodyChainRecorder<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }
}

impl<R: CustodyChainRecorder> CustodyChainRecorder for ContinuityEnforcingCustodyChainRecorder<R> {
    fn record_transfer(&mut self, transfer: CustodyTransfer) -> Result<(), ProvenanceError> {
        // If there is a current custodian, from_custodian must match
        if let Some(current) = self.inner.current_custodian(&transfer.artifact_ref)? {
            if current != transfer.from_custodian {
                return Err(ProvenanceError::InvalidOperation(
                    format!(
                        "custody continuity violation: current custodian is {}, but transfer claims from {}",
                        current, transfer.from_custodian
                    )
                ));
            }
        }
        self.inner.record_transfer(transfer)
    }

    fn transfers_for_artifact(&self, artifact_ref: &ArtifactRef) -> Result<Vec<CustodyTransfer>, ProvenanceError> {
        self.inner.transfers_for_artifact(artifact_ref)
    }

    fn current_custodian(&self, artifact_ref: &ArtifactRef) -> Result<Option<CustodianRef>, ProvenanceError> {
        self.inner.current_custodian(artifact_ref)
    }

    fn custody_snapshot(&self, artifact_ref: &ArtifactRef) -> Result<Option<CustodySnapshot>, ProvenanceError> {
        self.inner.custody_snapshot(artifact_ref)
    }

    fn transfer_count(&self) -> usize {
        self.inner.transfer_count()
    }

    fn recorder_id(&self) -> &str {
        self.inner.recorder_id()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn transfer(id: &str, artifact: &str, from: &str, to: &str, ts: i64) -> CustodyTransfer {
        CustodyTransfer {
            transfer_id: id.to_string(),
            artifact_ref: ArtifactRef::new(artifact),
            from_custodian: CustodianRef::new(from),
            to_custodian: CustodianRef::new(to),
            timestamp: ts,
            reason: "handoff".to_string(),
            signature_of_transfer: vec![1, 2, 3],
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_record_and_list_transfers() {
        let mut recorder = InMemoryCustodyChainRecorder::new("r1");
        recorder.record_transfer(transfer("t1", "art-1", "alice", "bob", 1000)).unwrap();
        recorder.record_transfer(transfer("t2", "art-1", "bob", "charlie", 2000)).unwrap();
        let transfers = recorder.transfers_for_artifact(&ArtifactRef::new("art-1")).unwrap();
        assert_eq!(transfers.len(), 2);
        assert_eq!(transfers[0].from_custodian.as_str(), "alice");
        assert_eq!(transfers[1].from_custodian.as_str(), "bob");
    }

    #[test]
    fn test_current_custodian() {
        let mut recorder = InMemoryCustodyChainRecorder::new("r1");
        recorder.record_transfer(transfer("t1", "art-1", "alice", "bob", 1000)).unwrap();
        recorder.record_transfer(transfer("t2", "art-1", "bob", "charlie", 2000)).unwrap();
        let current = recorder.current_custodian(&ArtifactRef::new("art-1")).unwrap().unwrap();
        assert_eq!(current.as_str(), "charlie");
    }

    #[test]
    fn test_current_custodian_none() {
        let recorder = InMemoryCustodyChainRecorder::new("r1");
        assert!(recorder.current_custodian(&ArtifactRef::new("art-1")).unwrap().is_none());
    }

    #[test]
    fn test_custody_snapshot() {
        let mut recorder = InMemoryCustodyChainRecorder::new("r1");
        recorder.record_transfer(transfer("t1", "art-1", "alice", "bob", 1000)).unwrap();
        recorder.record_transfer(transfer("t2", "art-1", "bob", "charlie", 2000)).unwrap();
        let snapshot = recorder.custody_snapshot(&ArtifactRef::new("art-1")).unwrap().unwrap();
        assert_eq!(snapshot.current_custodian.as_str(), "charlie");
        assert_eq!(snapshot.transfer_count, 2);
        assert_eq!(snapshot.first_transfer_at, Some(1000));
        assert_eq!(snapshot.last_transfer_at, Some(2000));
    }

    #[test]
    fn test_custody_snapshot_empty() {
        let recorder = InMemoryCustodyChainRecorder::new("r1");
        assert!(recorder.custody_snapshot(&ArtifactRef::new("art-1")).unwrap().is_none());
    }

    #[test]
    fn test_transfer_count() {
        let mut recorder = InMemoryCustodyChainRecorder::new("r1");
        recorder.record_transfer(transfer("t1", "art-1", "alice", "bob", 1000)).unwrap();
        recorder.record_transfer(transfer("t2", "art-2", "charlie", "dave", 2000)).unwrap();
        assert_eq!(recorder.transfer_count(), 2);
    }

    #[test]
    fn test_recorder_id() {
        let recorder = InMemoryCustodyChainRecorder::new("my-recorder");
        assert_eq!(recorder.recorder_id(), "my-recorder");
    }

    #[test]
    fn test_continuity_enforcing_allows_valid_chain() {
        let inner = InMemoryCustodyChainRecorder::new("r1");
        let mut recorder = ContinuityEnforcingCustodyChainRecorder::new(inner);
        recorder.record_transfer(transfer("t1", "art-1", "alice", "bob", 1000)).unwrap();
        recorder.record_transfer(transfer("t2", "art-1", "bob", "charlie", 2000)).unwrap();
        assert_eq!(recorder.transfer_count(), 2);
    }

    #[test]
    fn test_continuity_enforcing_rejects_gap() {
        let inner = InMemoryCustodyChainRecorder::new("r1");
        let mut recorder = ContinuityEnforcingCustodyChainRecorder::new(inner);
        recorder.record_transfer(transfer("t1", "art-1", "alice", "bob", 1000)).unwrap();
        // Gap: current custodian is bob, but transfer claims from charlie
        assert!(recorder.record_transfer(transfer("t2", "art-1", "charlie", "dave", 2000)).is_err());
    }

    #[test]
    fn test_continuity_enforcing_allows_first_transfer() {
        let inner = InMemoryCustodyChainRecorder::new("r1");
        let mut recorder = ContinuityEnforcingCustodyChainRecorder::new(inner);
        // First transfer has no prior custodian — should always succeed
        recorder.record_transfer(transfer("t1", "art-1", "alice", "bob", 1000)).unwrap();
    }

    #[test]
    fn test_separate_artifacts_independent() {
        let inner = InMemoryCustodyChainRecorder::new("r1");
        let mut recorder = ContinuityEnforcingCustodyChainRecorder::new(inner);
        recorder.record_transfer(transfer("t1", "art-1", "alice", "bob", 1000)).unwrap();
        // Different artifact — no continuity requirement with art-1
        recorder.record_transfer(transfer("t2", "art-2", "charlie", "dave", 2000)).unwrap();
    }

    #[test]
    fn test_multiple_artifacts_transfer_history() {
        let mut recorder = InMemoryCustodyChainRecorder::new("r1");
        recorder.record_transfer(transfer("t1", "art-1", "alice", "bob", 1000)).unwrap();
        recorder.record_transfer(transfer("t2", "art-2", "charlie", "dave", 1500)).unwrap();
        recorder.record_transfer(transfer("t3", "art-1", "bob", "eve", 2000)).unwrap();
        let art1_transfers = recorder.transfers_for_artifact(&ArtifactRef::new("art-1")).unwrap();
        assert_eq!(art1_transfers.len(), 2);
        let art2_transfers = recorder.transfers_for_artifact(&ArtifactRef::new("art-2")).unwrap();
        assert_eq!(art2_transfers.len(), 1);
    }
}
