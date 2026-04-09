// ═══════════════════════════════════════════════════════════════════════
// rune::audit — Audit Trail Access and Verification
//
// Public-facing API for querying, filtering, and verifying audit trails.
// Wraps the M5 runtime audit infrastructure with typed views,
// decision summaries, chain integrity checks, and export formats.
//
// Effect: io (export to file), otherwise pure queries on in-memory data.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::stdlib::crypto::hash::sha3_256_hex;

// ── AuditEventKind ─────────────────────────────────────────────────

/// Categorises what an audit entry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditEventKind {
    Decision,
    FunctionCall,
    CapabilityExercise,
    ModelAttestation,
    FfiCall,
}

impl fmt::Display for AuditEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decision => write!(f, "Decision"),
            Self::FunctionCall => write!(f, "FunctionCall"),
            Self::CapabilityExercise => write!(f, "CapabilityExercise"),
            Self::ModelAttestation => write!(f, "ModelAttestation"),
            Self::FfiCall => write!(f, "FfiCall"),
        }
    }
}

// ── AuditEntry ─────────────────────────────────────────────────────

/// A single record in the audit trail.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: u64,
    pub timestamp: u64,
    pub event_type: AuditEventKind,
    pub module_name: String,
    pub function_name: String,
    pub decision: Option<i32>,
    pub input_hash: String,
    pub record_hash: String,
}

impl AuditEntry {
    pub fn new(
        id: u64,
        timestamp: u64,
        event_type: AuditEventKind,
        module_name: &str,
        function_name: &str,
    ) -> Self {
        let input_hash = sha3_256_hex(
            format!("{}:{}:{}:{}", id, timestamp, module_name, function_name).as_bytes(),
        );
        let record_hash = sha3_256_hex(
            format!("{}:{}:{}", id, timestamp, input_hash).as_bytes(),
        );
        Self {
            id,
            timestamp,
            event_type,
            module_name: module_name.to_string(),
            function_name: function_name.to_string(),
            decision: None,
            input_hash,
            record_hash,
        }
    }

    pub fn with_decision(mut self, decision: i32) -> Self {
        self.decision = Some(decision);
        // Recompute record hash to include decision.
        self.record_hash = sha3_256_hex(
            format!("{}:{}:{}:{}", self.id, self.timestamp, self.input_hash, decision).as_bytes(),
        );
        self
    }
}

// ── AuditTrailView ─────────────────────────────────────────────────

/// Read-only view over a sequence of audit entries.
#[derive(Debug, Clone)]
pub struct AuditTrailView {
    entries: Vec<AuditEntry>,
}

impl AuditTrailView {
    pub fn new(entries: Vec<AuditEntry>) -> Self {
        Self { entries }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&AuditEntry> {
        self.entries.get(index)
    }

    /// Most recent entry (last by insertion order).
    pub fn latest(&self) -> Option<&AuditEntry> {
        self.entries.last()
    }

    /// All entries that carry a decision value.
    pub fn decisions(&self) -> Vec<&AuditEntry> {
        self.entries.iter().filter(|e| e.decision.is_some()).collect()
    }

    /// Filter by module name.
    pub fn by_module(&self, module: &str) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.module_name == module)
            .collect()
    }

    /// Filter by function name.
    pub fn by_function(&self, function: &str) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.function_name == function)
            .collect()
    }

    /// Entries with timestamp >= since.
    pub fn since(&self, since: u64) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.timestamp >= since)
            .collect()
    }

    /// Compute a summary of all decision entries.
    pub fn decision_summary(&self) -> DecisionSummary {
        let decision_entries = self.decisions();
        let total = decision_entries.len() as u64;
        let mut permits: u64 = 0;
        let mut denies: u64 = 0;
        let mut escalations: u64 = 0;
        let mut quarantines: u64 = 0;

        for entry in &decision_entries {
            match entry.decision {
                Some(0) => permits += 1,
                Some(1) => denies += 1,
                Some(2) => escalations += 1,
                Some(3) => quarantines += 1,
                _ => {}
            }
        }

        let permit_rate = if total > 0 {
            permits as f64 / total as f64
        } else {
            0.0
        };

        DecisionSummary {
            total,
            permits,
            denies,
            escalations,
            quarantines,
            permit_rate,
        }
    }
}

// ── DecisionSummary ────────────────────────────────────────────────

/// Aggregate statistics over decision audit entries.
#[derive(Debug, Clone)]
pub struct DecisionSummary {
    pub total: u64,
    pub permits: u64,
    pub denies: u64,
    pub escalations: u64,
    pub quarantines: u64,
    pub permit_rate: f64,
}

impl fmt::Display for DecisionSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "total={} permit={} deny={} escalate={} quarantine={} permit_rate={:.2}%",
            self.total,
            self.permits,
            self.denies,
            self.escalations,
            self.quarantines,
            self.permit_rate * 100.0
        )
    }
}

// ── Chain verification ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainIntegrity {
    Valid,
    Invalid { entry_id: u64, reason: String },
}

impl fmt::Display for ChainIntegrity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => write!(f, "chain integrity valid"),
            Self::Invalid { entry_id, reason } => {
                write!(f, "chain integrity failed at entry {entry_id}: {reason}")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditVerifyError {
    EmptyTrail,
    BrokenChain { entry_id: u64, reason: String },
}

impl fmt::Display for AuditVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTrail => write!(f, "audit trail is empty"),
            Self::BrokenChain { entry_id, reason } => {
                write!(f, "broken chain at entry {entry_id}: {reason}")
            }
        }
    }
}

impl std::error::Error for AuditVerifyError {}

/// Verify that record hashes are internally consistent.
pub fn verify_chain(trail: &AuditTrailView) -> Result<ChainIntegrity, AuditVerifyError> {
    if trail.is_empty() {
        return Err(AuditVerifyError::EmptyTrail);
    }

    for entry in &trail.entries {
        let expected = if let Some(decision) = entry.decision {
            sha3_256_hex(
                format!(
                    "{}:{}:{}:{}",
                    entry.id, entry.timestamp, entry.input_hash, decision
                )
                .as_bytes(),
            )
        } else {
            sha3_256_hex(
                format!("{}:{}:{}", entry.id, entry.timestamp, entry.input_hash).as_bytes(),
            )
        };

        if entry.record_hash != expected {
            return Ok(ChainIntegrity::Invalid {
                entry_id: entry.id,
                reason: "record hash mismatch".to_string(),
            });
        }
    }

    Ok(ChainIntegrity::Valid)
}

/// Convenience wrapper: returns Ok(()) if valid, Err if broken or empty.
pub fn verify_integrity(trail: &AuditTrailView) -> Result<(), AuditVerifyError> {
    match verify_chain(trail)? {
        ChainIntegrity::Valid => Ok(()),
        ChainIntegrity::Invalid { entry_id, reason } => {
            Err(AuditVerifyError::BrokenChain { entry_id, reason })
        }
    }
}

// ── Export ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Csv,
}

/// Export trail entries as JSON lines.
pub fn to_json(trail: &AuditTrailView) -> String {
    let mut lines = Vec::with_capacity(trail.len());
    for entry in &trail.entries {
        let decision_str = match entry.decision {
            Some(d) => d.to_string(),
            None => "null".to_string(),
        };
        lines.push(format!(
            r#"{{"id":{},"timestamp":{},"event_type":"{}","module":"{}","function":"{}","decision":{},"input_hash":"{}","record_hash":"{}"}}"#,
            entry.id,
            entry.timestamp,
            entry.event_type,
            entry.module_name,
            entry.function_name,
            decision_str,
            entry.input_hash,
            entry.record_hash,
        ));
    }
    lines.join("\n")
}

/// Export trail entries as CSV.
pub fn to_csv(trail: &AuditTrailView) -> String {
    let mut out = String::from("id,timestamp,event_type,module,function,decision,input_hash,record_hash\n");
    for entry in &trail.entries {
        let decision_str = match entry.decision {
            Some(d) => d.to_string(),
            None => String::new(),
        };
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            entry.id,
            entry.timestamp,
            entry.event_type,
            entry.module_name,
            entry.function_name,
            decision_str,
            entry.input_hash,
            entry.record_hash,
        ));
    }
    out
}

/// Write trail to a file in the given format. Requires `io` effect.
pub fn write_to_file(
    trail: &AuditTrailView,
    path: &str,
    format: ExportFormat,
) -> std::io::Result<()> {
    let content = match format {
        ExportFormat::Json => to_json(trail),
        ExportFormat::Csv => to_csv(trail),
    };
    std::fs::write(path, content)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(id: u64, ts: u64, kind: AuditEventKind, decision: Option<i32>) -> AuditEntry {
        let mut entry = AuditEntry::new(id, ts, kind, "access_control", "evaluate");
        if let Some(d) = decision {
            entry = entry.with_decision(d);
        }
        entry
    }

    fn sample_trail() -> AuditTrailView {
        AuditTrailView::new(vec![
            sample_entry(1, 1000, AuditEventKind::Decision, Some(0)),
            sample_entry(2, 2000, AuditEventKind::Decision, Some(1)),
            sample_entry(3, 3000, AuditEventKind::FunctionCall, None),
            sample_entry(4, 4000, AuditEventKind::Decision, Some(0)),
            sample_entry(5, 5000, AuditEventKind::Decision, Some(2)),
        ])
    }

    #[test]
    fn test_audit_entry_construction() {
        let entry = AuditEntry::new(1, 1000, AuditEventKind::Decision, "mod_a", "func_b");
        assert_eq!(entry.id, 1);
        assert_eq!(entry.timestamp, 1000);
        assert_eq!(entry.event_type, AuditEventKind::Decision);
        assert_eq!(entry.module_name, "mod_a");
        assert_eq!(entry.function_name, "func_b");
        assert!(entry.decision.is_none());
        assert!(!entry.input_hash.is_empty());
        assert!(!entry.record_hash.is_empty());
    }

    #[test]
    fn test_audit_entry_with_decision() {
        let entry = AuditEntry::new(1, 1000, AuditEventKind::Decision, "m", "f")
            .with_decision(0);
        assert_eq!(entry.decision, Some(0));
        // Record hash changes when decision is added.
        let no_decision = AuditEntry::new(1, 1000, AuditEventKind::Decision, "m", "f");
        assert_ne!(entry.record_hash, no_decision.record_hash);
    }

    #[test]
    fn test_audit_event_kind_display() {
        assert_eq!(AuditEventKind::Decision.to_string(), "Decision");
        assert_eq!(AuditEventKind::FunctionCall.to_string(), "FunctionCall");
        assert_eq!(AuditEventKind::CapabilityExercise.to_string(), "CapabilityExercise");
        assert_eq!(AuditEventKind::ModelAttestation.to_string(), "ModelAttestation");
        assert_eq!(AuditEventKind::FfiCall.to_string(), "FfiCall");
    }

    #[test]
    fn test_trail_view_len_and_empty() {
        let trail = sample_trail();
        assert_eq!(trail.len(), 5);
        assert!(!trail.is_empty());

        let empty = AuditTrailView::new(vec![]);
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn test_trail_view_get_and_latest() {
        let trail = sample_trail();
        assert_eq!(trail.get(0).unwrap().id, 1);
        assert_eq!(trail.latest().unwrap().id, 5);
        assert!(trail.get(99).is_none());
    }

    #[test]
    fn test_trail_view_decisions() {
        let trail = sample_trail();
        let decisions = trail.decisions();
        assert_eq!(decisions.len(), 4);
        // Entry 3 (FunctionCall, no decision) is excluded.
        assert!(decisions.iter().all(|e| e.decision.is_some()));
    }

    #[test]
    fn test_trail_view_by_module() {
        let mut entries = vec![
            AuditEntry::new(1, 1000, AuditEventKind::Decision, "mod_a", "f"),
            AuditEntry::new(2, 2000, AuditEventKind::Decision, "mod_b", "f"),
            AuditEntry::new(3, 3000, AuditEventKind::Decision, "mod_a", "g"),
        ];
        entries[0] = entries[0].clone().with_decision(0);
        entries[1] = entries[1].clone().with_decision(1);
        entries[2] = entries[2].clone().with_decision(0);
        let trail = AuditTrailView::new(entries);
        assert_eq!(trail.by_module("mod_a").len(), 2);
        assert_eq!(trail.by_module("mod_b").len(), 1);
        assert_eq!(trail.by_module("mod_c").len(), 0);
    }

    #[test]
    fn test_trail_view_by_function() {
        let trail = sample_trail();
        assert_eq!(trail.by_function("evaluate").len(), 5);
        assert_eq!(trail.by_function("nonexistent").len(), 0);
    }

    #[test]
    fn test_trail_view_since() {
        let trail = sample_trail();
        assert_eq!(trail.since(3000).len(), 3);
        assert_eq!(trail.since(6000).len(), 0);
        assert_eq!(trail.since(0).len(), 5);
    }

    #[test]
    fn test_decision_summary() {
        let trail = sample_trail();
        let summary = trail.decision_summary();
        assert_eq!(summary.total, 4);
        assert_eq!(summary.permits, 2);
        assert_eq!(summary.denies, 1);
        assert_eq!(summary.escalations, 1);
        assert_eq!(summary.quarantines, 0);
        assert!((summary.permit_rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_decision_summary_display() {
        let trail = sample_trail();
        let s = trail.decision_summary().to_string();
        assert!(s.contains("total=4"));
        assert!(s.contains("permit=2"));
        assert!(s.contains("deny=1"));
        assert!(s.contains("50.00%"));
    }

    #[test]
    fn test_decision_summary_empty() {
        let trail = AuditTrailView::new(vec![]);
        let summary = trail.decision_summary();
        assert_eq!(summary.total, 0);
        assert_eq!(summary.permit_rate, 0.0);
    }

    #[test]
    fn test_verify_chain_valid() {
        let trail = sample_trail();
        assert_eq!(verify_chain(&trail).unwrap(), ChainIntegrity::Valid);
    }

    #[test]
    fn test_verify_chain_empty() {
        let trail = AuditTrailView::new(vec![]);
        assert_eq!(verify_chain(&trail).unwrap_err(), AuditVerifyError::EmptyTrail);
    }

    #[test]
    fn test_verify_chain_tampered() {
        let mut entries = vec![sample_entry(1, 1000, AuditEventKind::Decision, Some(0))];
        entries[0].record_hash = "tampered".to_string();
        let trail = AuditTrailView::new(entries);
        match verify_chain(&trail).unwrap() {
            ChainIntegrity::Invalid { entry_id, .. } => assert_eq!(entry_id, 1),
            _ => panic!("expected invalid"),
        }
    }

    #[test]
    fn test_verify_integrity_ok() {
        let trail = sample_trail();
        assert!(verify_integrity(&trail).is_ok());
    }

    #[test]
    fn test_verify_integrity_empty() {
        let trail = AuditTrailView::new(vec![]);
        assert!(matches!(
            verify_integrity(&trail),
            Err(AuditVerifyError::EmptyTrail)
        ));
    }

    #[test]
    fn test_to_json() {
        let trail = AuditTrailView::new(vec![
            sample_entry(1, 1000, AuditEventKind::Decision, Some(0)),
        ]);
        let json = to_json(&trail);
        assert!(json.contains(r#""id":1"#));
        assert!(json.contains(r#""timestamp":1000"#));
        assert!(json.contains(r#""event_type":"Decision""#));
        assert!(json.contains(r#""decision":0"#));
    }

    #[test]
    fn test_to_csv() {
        let trail = AuditTrailView::new(vec![
            sample_entry(1, 1000, AuditEventKind::Decision, Some(0)),
        ]);
        let csv = to_csv(&trail);
        assert!(csv.starts_with("id,timestamp,event_type,module,function,decision,input_hash,record_hash\n"));
        assert!(csv.contains("1,1000,Decision,access_control,evaluate,0,"));
    }

    #[test]
    fn test_write_to_file_json() {
        let trail = AuditTrailView::new(vec![
            sample_entry(1, 1000, AuditEventKind::Decision, Some(0)),
        ]);
        let path = "/tmp/rune_audit_test.json";
        write_to_file(&trail, path, ExportFormat::Json).unwrap();
        let content = std::fs::read_to_string(path).unwrap();
        assert!(content.contains(r#""id":1"#));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_audit_verify_error_display() {
        assert_eq!(AuditVerifyError::EmptyTrail.to_string(), "audit trail is empty");
        let err = AuditVerifyError::BrokenChain {
            entry_id: 42,
            reason: "hash mismatch".into(),
        };
        assert!(err.to_string().contains("42"));
        assert!(err.to_string().contains("hash mismatch"));
    }
}
