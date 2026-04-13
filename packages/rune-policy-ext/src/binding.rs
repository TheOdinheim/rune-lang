// ═══════════════════════════════════════════════════════════════════════
// Binding — Map policies to regulatory framework requirements.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::policy::*;

// ── BindingCoverage ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindingCoverage {
    Full,
    Partial { gap: String },
    Planned,
    NotApplicable,
}

impl fmt::Display for BindingCoverage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => f.write_str("Full"),
            Self::Partial { gap } => write!(f, "Partial (gap: {gap})"),
            Self::Planned => f.write_str("Planned"),
            Self::NotApplicable => f.write_str("NotApplicable"),
        }
    }
}

// ── FrameworkBinding ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkBinding {
    pub framework: String,
    pub requirement_id: String,
    pub requirement_description: String,
    pub coverage: BindingCoverage,
    pub notes: Option<String>,
}

impl FrameworkBinding {
    pub fn new(
        framework: impl Into<String>,
        requirement_id: impl Into<String>,
        description: impl Into<String>,
        coverage: BindingCoverage,
    ) -> Self {
        Self {
            framework: framework.into(),
            requirement_id: requirement_id.into(),
            requirement_description: description.into(),
            coverage,
            notes: None,
        }
    }

    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }
}

// ── FrameworkCoverageSummary ────────────────────────────────────────

pub struct FrameworkCoverageSummary {
    pub framework: String,
    pub total_bindings: usize,
    pub full_coverage: usize,
    pub partial_coverage: usize,
    pub planned: usize,
    pub not_applicable: usize,
    pub coverage_rate: f64,
}

impl fmt::Display for FrameworkCoverageSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}/{} covered ({:.0}%), {} partial, {} planned",
            self.framework,
            self.full_coverage,
            self.total_bindings,
            self.coverage_rate * 100.0,
            self.partial_coverage,
            self.planned,
        )
    }
}

// ── FrameworkBindingRegistry ────────────────────────────────────────

pub struct FrameworkBindingRegistry {
    bindings: HashMap<ManagedPolicyId, Vec<FrameworkBinding>>,
}

impl FrameworkBindingRegistry {
    pub fn new() -> Self {
        Self {
            bindings: HashMap::new(),
        }
    }

    pub fn bind(&mut self, policy_id: ManagedPolicyId, binding: FrameworkBinding) {
        self.bindings.entry(policy_id).or_default().push(binding);
    }

    pub fn bindings_for(&self, policy_id: &ManagedPolicyId) -> Vec<&FrameworkBinding> {
        self.bindings
            .get(policy_id)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    pub fn policies_for_framework(&self, framework: &str) -> Vec<(&ManagedPolicyId, &FrameworkBinding)> {
        self.bindings
            .iter()
            .flat_map(|(pid, bindings)| {
                bindings
                    .iter()
                    .filter(|b| b.framework == framework)
                    .map(move |b| (pid, b))
            })
            .collect()
    }

    pub fn policies_for_requirement(
        &self,
        framework: &str,
        requirement_id: &str,
    ) -> Vec<(&ManagedPolicyId, &FrameworkBinding)> {
        self.bindings
            .iter()
            .flat_map(|(pid, bindings)| {
                bindings
                    .iter()
                    .filter(|b| b.framework == framework && b.requirement_id == requirement_id)
                    .map(move |b| (pid, b))
            })
            .collect()
    }

    pub fn coverage_summary(&self, framework: &str) -> FrameworkCoverageSummary {
        let all: Vec<&FrameworkBinding> = self
            .bindings
            .values()
            .flatten()
            .filter(|b| b.framework == framework)
            .collect();

        let total = all.len();
        let full = all.iter().filter(|b| matches!(b.coverage, BindingCoverage::Full)).count();
        let partial = all
            .iter()
            .filter(|b| matches!(b.coverage, BindingCoverage::Partial { .. }))
            .count();
        let planned = all.iter().filter(|b| matches!(b.coverage, BindingCoverage::Planned)).count();
        let na = all
            .iter()
            .filter(|b| matches!(b.coverage, BindingCoverage::NotApplicable))
            .count();

        let rate = if total > 0 {
            (full + partial) as f64 / total as f64
        } else {
            0.0
        };

        FrameworkCoverageSummary {
            framework: framework.into(),
            total_bindings: total,
            full_coverage: full,
            partial_coverage: partial,
            planned,
            not_applicable: na,
            coverage_rate: rate,
        }
    }

    pub fn unbound_policies<'a>(&self, store: &'a ManagedPolicyStore) -> Vec<&'a ManagedPolicyId> {
        store
            .all_ids()
            .into_iter()
            .filter(|id| !self.bindings.contains_key(id))
            .collect()
    }

    pub fn gaps(&self, framework: &str) -> Vec<&FrameworkBinding> {
        self.bindings
            .values()
            .flatten()
            .filter(|b| b.framework == framework && matches!(b.coverage, BindingCoverage::Partial { .. }))
            .collect()
    }
}

impl Default for FrameworkBindingRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_and_bindings_for() {
        let mut reg = FrameworkBindingRegistry::new();
        let pid = ManagedPolicyId::new("p1");
        reg.bind(
            pid.clone(),
            FrameworkBinding::new("GDPR", "Art. 5(1)(f)", "Security of processing", BindingCoverage::Full),
        );
        assert_eq!(reg.bindings_for(&pid).len(), 1);
    }

    #[test]
    fn test_policies_for_framework() {
        let mut reg = FrameworkBindingRegistry::new();
        reg.bind(
            ManagedPolicyId::new("p1"),
            FrameworkBinding::new("GDPR", "Art. 5(1)(f)", "Security", BindingCoverage::Full),
        );
        reg.bind(
            ManagedPolicyId::new("p2"),
            FrameworkBinding::new("NIST AI RMF", "GOVERN-1.1", "AI governance", BindingCoverage::Planned),
        );
        assert_eq!(reg.policies_for_framework("GDPR").len(), 1);
        assert_eq!(reg.policies_for_framework("NIST AI RMF").len(), 1);
    }

    #[test]
    fn test_policies_for_requirement() {
        let mut reg = FrameworkBindingRegistry::new();
        reg.bind(
            ManagedPolicyId::new("p1"),
            FrameworkBinding::new("CMMC", "AC.L1-3.1.1", "Access control", BindingCoverage::Full),
        );
        reg.bind(
            ManagedPolicyId::new("p2"),
            FrameworkBinding::new("CMMC", "AC.L1-3.1.1", "Access control", BindingCoverage::Partial { gap: "no MFA".into() }),
        );
        assert_eq!(reg.policies_for_requirement("CMMC", "AC.L1-3.1.1").len(), 2);
    }

    #[test]
    fn test_coverage_summary() {
        let mut reg = FrameworkBindingRegistry::new();
        reg.bind(
            ManagedPolicyId::new("p1"),
            FrameworkBinding::new("GDPR", "Art. 5", "Integrity", BindingCoverage::Full),
        );
        reg.bind(
            ManagedPolicyId::new("p2"),
            FrameworkBinding::new("GDPR", "Art. 32", "Security", BindingCoverage::Partial { gap: "missing encryption".into() }),
        );
        reg.bind(
            ManagedPolicyId::new("p3"),
            FrameworkBinding::new("GDPR", "Art. 35", "DPIA", BindingCoverage::Planned),
        );
        let summary = reg.coverage_summary("GDPR");
        assert_eq!(summary.total_bindings, 3);
        assert_eq!(summary.full_coverage, 1);
        assert_eq!(summary.partial_coverage, 1);
        assert_eq!(summary.planned, 1);
        assert!((summary.coverage_rate - 2.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_gaps() {
        let mut reg = FrameworkBindingRegistry::new();
        reg.bind(
            ManagedPolicyId::new("p1"),
            FrameworkBinding::new("GDPR", "Art. 5", "Integrity", BindingCoverage::Full),
        );
        reg.bind(
            ManagedPolicyId::new("p2"),
            FrameworkBinding::new("GDPR", "Art. 32", "Security", BindingCoverage::Partial { gap: "no encryption".into() }),
        );
        let gaps = reg.gaps("GDPR");
        assert_eq!(gaps.len(), 1);
    }

    #[test]
    fn test_unbound_policies() {
        let mut store = ManagedPolicyStore::new();
        store
            .add(ManagedPolicy::new("p1", "A", PolicyDomain::AccessControl, "t", 1000))
            .unwrap();
        store
            .add(ManagedPolicy::new("p2", "B", PolicyDomain::Privacy, "t", 1000))
            .unwrap();
        let mut reg = FrameworkBindingRegistry::new();
        reg.bind(
            ManagedPolicyId::new("p1"),
            FrameworkBinding::new("GDPR", "Art. 5", "x", BindingCoverage::Full),
        );
        let unbound = reg.unbound_policies(&store);
        assert_eq!(unbound.len(), 1);
        assert_eq!(unbound[0], &ManagedPolicyId::new("p2"));
    }

    #[test]
    fn test_binding_coverage_display() {
        assert_eq!(BindingCoverage::Full.to_string(), "Full");
        assert_eq!(
            BindingCoverage::Partial { gap: "no MFA".into() }.to_string(),
            "Partial (gap: no MFA)"
        );
        assert_eq!(BindingCoverage::Planned.to_string(), "Planned");
        assert_eq!(BindingCoverage::NotApplicable.to_string(), "NotApplicable");
    }

    #[test]
    fn test_coverage_summary_display() {
        let summary = FrameworkCoverageSummary {
            framework: "GDPR".into(),
            total_bindings: 10,
            full_coverage: 7,
            partial_coverage: 2,
            planned: 1,
            not_applicable: 0,
            coverage_rate: 0.9,
        };
        let display = summary.to_string();
        assert!(display.contains("GDPR"));
        assert!(display.contains("7/10"));
    }
}
