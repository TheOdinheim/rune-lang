// ═══════════════════════════════════════════════════════════════════════
// Quarantine Store
//
// Suspicious inputs/outputs are held in a quarantine store for human
// review rather than being blocked or released immediately.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use rune_security::SecuritySeverity;
use serde::{Deserialize, Serialize};

use crate::error::ShieldError;

// ── QuarantineId ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QuarantineId(pub String);

impl QuarantineId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for QuarantineId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── QuarantineContentType ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuarantineContentType {
    Input,
    Output,
    Request,
}

// ── QuarantineVerdict ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum QuarantineVerdict {
    Released,
    Confirmed { reason: String },
    FalsePositive { reason: String },
    Modified { new_content: String },
}

impl QuarantineVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Released => "Released",
            Self::Confirmed { .. } => "Confirmed",
            Self::FalsePositive { .. } => "FalsePositive",
            Self::Modified { .. } => "Modified",
        }
    }
}

// ── QuarantineEntry ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct QuarantineEntry {
    pub id: QuarantineId,
    pub content_type: QuarantineContentType,
    pub content: String,
    pub reason: String,
    pub severity: SecuritySeverity,
    pub confidence: f64,
    pub created_at: i64,
    pub reviewed_at: Option<i64>,
    pub verdict: Option<QuarantineVerdict>,
}

impl QuarantineEntry {
    pub fn is_pending(&self) -> bool {
        self.verdict.is_none()
    }

    pub fn review_duration_ms(&self) -> Option<i64> {
        self.reviewed_at.map(|r| r - self.created_at)
    }
}

// ── QuarantineStore ───────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct QuarantineStore {
    pub entries: HashMap<QuarantineId, QuarantineEntry>,
    next_id: u64,
    total_confirmed: usize,
    total_false_positive: usize,
}

impl QuarantineStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn alloc_id(&mut self) -> QuarantineId {
        self.next_id += 1;
        QuarantineId(format!("Q-{:08}", self.next_id))
    }

    pub fn quarantine(
        &mut self,
        content_type: QuarantineContentType,
        content: impl Into<String>,
        reason: impl Into<String>,
        severity: SecuritySeverity,
        confidence: f64,
        timestamp: i64,
    ) -> QuarantineId {
        let id = self.alloc_id();
        let entry = QuarantineEntry {
            id: id.clone(),
            content_type,
            content: content.into(),
            reason: reason.into(),
            severity,
            confidence,
            created_at: timestamp,
            reviewed_at: None,
            verdict: None,
        };
        self.entries.insert(id.clone(), entry);
        id
    }

    pub fn get(&self, id: &QuarantineId) -> Option<&QuarantineEntry> {
        self.entries.get(id)
    }

    pub fn review(
        &mut self,
        id: &QuarantineId,
        verdict: QuarantineVerdict,
        timestamp: i64,
    ) -> Result<(), ShieldError> {
        let entry = self
            .entries
            .get_mut(id)
            .ok_or_else(|| ShieldError::QuarantineNotFound(id.0.clone()))?;
        if entry.verdict.is_some() {
            return Err(ShieldError::QuarantineAlreadyReviewed(id.0.clone()));
        }
        match &verdict {
            QuarantineVerdict::Confirmed { .. } => self.total_confirmed += 1,
            QuarantineVerdict::FalsePositive { .. } => self.total_false_positive += 1,
            _ => {}
        }
        entry.verdict = Some(verdict);
        entry.reviewed_at = Some(timestamp);
        Ok(())
    }

    pub fn pending_review(&self) -> Vec<&QuarantineEntry> {
        self.entries.values().filter(|e| e.is_pending()).collect()
    }

    pub fn reviewed(&self) -> Vec<&QuarantineEntry> {
        self.entries.values().filter(|e| !e.is_pending()).collect()
    }

    pub fn false_positive_rate(&self) -> f64 {
        let total = self.total_confirmed + self.total_false_positive;
        if total == 0 {
            0.0
        } else {
            self.total_false_positive as f64 / total as f64
        }
    }

    pub fn average_review_time_ms(&self) -> Option<f64> {
        let durations: Vec<i64> = self
            .entries
            .values()
            .filter_map(|e| e.review_duration_ms())
            .collect();
        if durations.is_empty() {
            None
        } else {
            Some(durations.iter().sum::<i64>() as f64 / durations.len() as f64)
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> QuarantineStore {
        QuarantineStore::new()
    }

    #[test]
    fn test_quarantine_and_get() {
        let mut s = make_store();
        let id = s.quarantine(
            QuarantineContentType::Input,
            "suspicious text",
            "injection suspected",
            SecuritySeverity::High,
            0.8,
            1000,
        );
        assert!(s.get(&id).is_some());
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn test_pending_review_filter() {
        let mut s = make_store();
        s.quarantine(
            QuarantineContentType::Input,
            "a",
            "r",
            SecuritySeverity::High,
            0.9,
            1000,
        );
        assert_eq!(s.pending_review().len(), 1);
        assert_eq!(s.reviewed().len(), 0);
    }

    #[test]
    fn test_review_confirmed() {
        let mut s = make_store();
        let id = s.quarantine(
            QuarantineContentType::Input,
            "a",
            "r",
            SecuritySeverity::High,
            0.9,
            1000,
        );
        s.review(
            &id,
            QuarantineVerdict::Confirmed { reason: "injection".into() },
            1500,
        )
        .unwrap();
        assert!(!s.get(&id).unwrap().is_pending());
        assert_eq!(s.reviewed().len(), 1);
    }

    #[test]
    fn test_review_false_positive_affects_rate() {
        let mut s = make_store();
        let id1 = s.quarantine(
            QuarantineContentType::Input,
            "a",
            "r",
            SecuritySeverity::High,
            0.9,
            1000,
        );
        let id2 = s.quarantine(
            QuarantineContentType::Input,
            "b",
            "r",
            SecuritySeverity::High,
            0.9,
            1000,
        );
        s.review(
            &id1,
            QuarantineVerdict::FalsePositive { reason: "benign".into() },
            1500,
        )
        .unwrap();
        s.review(
            &id2,
            QuarantineVerdict::Confirmed { reason: "bad".into() },
            1500,
        )
        .unwrap();
        assert!((s.false_positive_rate() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_review_not_found() {
        let mut s = make_store();
        let r = s.review(
            &QuarantineId::new("nope"),
            QuarantineVerdict::Released,
            1000,
        );
        assert!(matches!(r, Err(ShieldError::QuarantineNotFound(_))));
    }

    #[test]
    fn test_double_review_errors() {
        let mut s = make_store();
        let id = s.quarantine(
            QuarantineContentType::Input,
            "a",
            "r",
            SecuritySeverity::High,
            0.9,
            1000,
        );
        s.review(&id, QuarantineVerdict::Released, 1500).unwrap();
        let r = s.review(&id, QuarantineVerdict::Released, 2000);
        assert!(matches!(r, Err(ShieldError::QuarantineAlreadyReviewed(_))));
    }

    #[test]
    fn test_average_review_time() {
        let mut s = make_store();
        let id1 = s.quarantine(
            QuarantineContentType::Input,
            "a",
            "r",
            SecuritySeverity::High,
            0.9,
            1000,
        );
        let id2 = s.quarantine(
            QuarantineContentType::Input,
            "b",
            "r",
            SecuritySeverity::High,
            0.9,
            2000,
        );
        s.review(&id1, QuarantineVerdict::Released, 1500).unwrap();
        s.review(&id2, QuarantineVerdict::Released, 3000).unwrap();
        let avg = s.average_review_time_ms().unwrap();
        assert!((avg - 750.0).abs() < 1e-9);
    }

    #[test]
    fn test_empty_false_positive_rate_is_zero() {
        let s = make_store();
        assert_eq!(s.false_positive_rate(), 0.0);
    }

    #[test]
    fn test_modified_verdict() {
        let mut s = make_store();
        let id = s.quarantine(
            QuarantineContentType::Output,
            "secret: sk-123",
            "exfil",
            SecuritySeverity::Critical,
            0.9,
            1000,
        );
        s.review(
            &id,
            QuarantineVerdict::Modified { new_content: "secret: [REDACTED]".into() },
            1500,
        )
        .unwrap();
        let e = s.get(&id).unwrap();
        assert_eq!(e.verdict.as_ref().unwrap().as_str(), "Modified");
    }

    #[test]
    fn test_sequential_ids_unique() {
        let mut s = make_store();
        let a = s.quarantine(
            QuarantineContentType::Input,
            "a",
            "r",
            SecuritySeverity::High,
            0.9,
            1000,
        );
        let b = s.quarantine(
            QuarantineContentType::Input,
            "b",
            "r",
            SecuritySeverity::High,
            0.9,
            1000,
        );
        assert_ne!(a, b);
    }
}
