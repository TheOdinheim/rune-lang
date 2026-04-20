// ═══════════════════════════════════════════════════════════════════════
// Correlation — Finding correlation trait and reference implementations.
//
// Layer 3 defines the contract for correlating detection findings
// across time, source, and attribute dimensions. The existing
// AlertCorrelator struct in alert.rs handles Layer 2 alert-level
// correlation; this trait defines the pluggable Layer 3 boundary
// for finding-level correlation engines.
//
// Named FindingCorrelator to avoid collision with the existing
// AlertCorrelator struct re-exported from alert.rs.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::backend::DetectionFinding;
use crate::error::DetectionError;

// ── CorrelationResult ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationResult {
    pub correlation_id: String,
    pub related_finding_ids: Vec<String>,
    pub correlation_type: String,
    pub confidence: String, // String for Eq derivation (no f64)
    pub explanation: String,
}

impl CorrelationResult {
    pub fn new(
        correlation_id: &str,
        finding_ids: Vec<String>,
        correlation_type: &str,
        confidence: &str,
        explanation: &str,
    ) -> Self {
        Self {
            correlation_id: correlation_id.to_string(),
            related_finding_ids: finding_ids,
            correlation_type: correlation_type.to_string(),
            confidence: confidence.to_string(),
            explanation: explanation.to_string(),
        }
    }

    pub fn finding_count(&self) -> usize {
        self.related_finding_ids.len()
    }
}

// ── FindingCorrelator trait ────────────────────────────────────

pub trait FindingCorrelator {
    fn correlate(&self, findings: &[&DetectionFinding]) -> Result<Vec<CorrelationResult>, DetectionError>;
    fn correlation_rule_id(&self) -> &str;
    fn supported_correlation_types(&self) -> Vec<&str>;
    fn is_active(&self) -> bool;
}

// ── TimeWindowCorrelator ───────────────────────────────────────

/// Groups findings within a time window when at least N findings
/// share a subject identifier (source field).
pub struct TimeWindowCorrelator {
    rule_id: String,
    window_seconds: i64,
    min_count: usize,
    active: bool,
}

impl TimeWindowCorrelator {
    pub fn new(rule_id: &str, window_seconds: i64, min_count: usize) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            window_seconds,
            min_count,
            active: true,
        }
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl FindingCorrelator for TimeWindowCorrelator {
    fn correlate(&self, findings: &[&DetectionFinding]) -> Result<Vec<CorrelationResult>, DetectionError> {
        if findings.is_empty() {
            return Ok(Vec::new());
        }

        // Group findings by source (subject identifier)
        let mut by_source: HashMap<&str, Vec<&DetectionFinding>> = HashMap::new();
        for f in findings {
            by_source.entry(f.source.as_str()).or_default().push(f);
        }

        let mut results = Vec::new();
        let mut correlation_counter = 0u64;

        for (source, group) in &by_source {
            if group.len() < self.min_count {
                continue;
            }

            // Find clusters within the time window
            let mut sorted: Vec<&&DetectionFinding> = group.iter().collect();
            sorted.sort_by_key(|f| f.timestamp);

            let mut window_start = 0;
            for window_end in 0..sorted.len() {
                while sorted[window_end].timestamp - sorted[window_start].timestamp > self.window_seconds {
                    window_start += 1;
                }
                let window_size = window_end - window_start + 1;
                if window_size >= self.min_count && window_end == sorted.len() - 1 {
                    let ids: Vec<String> = sorted[window_start..=window_end]
                        .iter()
                        .map(|f| f.id.clone())
                        .collect();
                    let confidence = format!("{:.3}", f64::min(1.0, window_size as f64 / self.min_count as f64));
                    correlation_counter += 1;
                    results.push(CorrelationResult::new(
                        &format!("{}-{correlation_counter}", self.rule_id),
                        ids,
                        "time-window",
                        &confidence,
                        &format!("{window_size} findings from source '{source}' within {}s window", self.window_seconds),
                    ));
                }
            }
        }

        Ok(results)
    }

    fn correlation_rule_id(&self) -> &str {
        &self.rule_id
    }

    fn supported_correlation_types(&self) -> Vec<&str> {
        vec!["time-window"]
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── AttributeCorrelator ────────────────────────────────────────

/// Groups findings by a shared attribute value (category field).
pub struct AttributeCorrelator {
    rule_id: String,
    min_count: usize,
    active: bool,
}

impl AttributeCorrelator {
    pub fn new(rule_id: &str, min_count: usize) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            min_count,
            active: true,
        }
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl FindingCorrelator for AttributeCorrelator {
    fn correlate(&self, findings: &[&DetectionFinding]) -> Result<Vec<CorrelationResult>, DetectionError> {
        // Group findings by category
        let mut by_category: HashMap<&str, Vec<&DetectionFinding>> = HashMap::new();
        for f in findings {
            if !f.category.is_empty() {
                by_category.entry(f.category.as_str()).or_default().push(f);
            }
        }

        let mut results = Vec::new();
        let mut correlation_counter = 0u64;

        for (category, group) in &by_category {
            if group.len() >= self.min_count {
                let ids: Vec<String> = group.iter().map(|f| f.id.clone()).collect();
                let confidence = format!("{:.3}", f64::min(1.0, group.len() as f64 / self.min_count as f64));
                correlation_counter += 1;
                results.push(CorrelationResult::new(
                    &format!("{}-{correlation_counter}", self.rule_id),
                    ids,
                    "attribute",
                    &confidence,
                    &format!("{} findings share category '{category}'", group.len()),
                ));
            }
        }

        Ok(results)
    }

    fn correlation_rule_id(&self) -> &str {
        &self.rule_id
    }

    fn supported_correlation_types(&self) -> Vec<&str> {
        vec!["attribute"]
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use rune_security::SecuritySeverity;

    fn make_finding(id: &str, category: &str, source: &str, ts: i64) -> DetectionFinding {
        DetectionFinding::new(id, "Test", SecuritySeverity::High, ts)
            .with_category(category)
            .with_source(source)
    }

    #[test]
    fn test_time_window_correlator_basic() {
        let correlator = TimeWindowCorrelator::new("tw-1", 100, 2);
        let f1 = make_finding("f1", "injection", "src-1", 1000);
        let f2 = make_finding("f2", "injection", "src-1", 1050);
        let results = correlator.correlate(&[&f1, &f2]).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].correlation_type, "time-window");
        assert_eq!(results[0].finding_count(), 2);
    }

    #[test]
    fn test_time_window_correlator_outside_window() {
        let correlator = TimeWindowCorrelator::new("tw-1", 100, 2);
        let f1 = make_finding("f1", "injection", "src-1", 1000);
        let f2 = make_finding("f2", "injection", "src-1", 2000);
        let results = correlator.correlate(&[&f1, &f2]).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_time_window_correlator_different_sources() {
        let correlator = TimeWindowCorrelator::new("tw-1", 100, 2);
        let f1 = make_finding("f1", "injection", "src-1", 1000);
        let f2 = make_finding("f2", "injection", "src-2", 1050);
        let results = correlator.correlate(&[&f1, &f2]).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_time_window_correlator_below_min_count() {
        let correlator = TimeWindowCorrelator::new("tw-1", 100, 3);
        let f1 = make_finding("f1", "injection", "src-1", 1000);
        let f2 = make_finding("f2", "injection", "src-1", 1050);
        let results = correlator.correlate(&[&f1, &f2]).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_time_window_correlator_empty() {
        let correlator = TimeWindowCorrelator::new("tw-1", 100, 2);
        let results = correlator.correlate(&[]).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_attribute_correlator_basic() {
        let correlator = AttributeCorrelator::new("attr-1", 2);
        let f1 = make_finding("f1", "injection", "src-1", 1000);
        let f2 = make_finding("f2", "injection", "src-2", 2000);
        let f3 = make_finding("f3", "exfiltration", "src-1", 1500);
        let results = correlator.correlate(&[&f1, &f2, &f3]).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].correlation_type, "attribute");
        assert_eq!(results[0].finding_count(), 2);
    }

    #[test]
    fn test_attribute_correlator_below_min_count() {
        let correlator = AttributeCorrelator::new("attr-1", 3);
        let f1 = make_finding("f1", "injection", "src-1", 1000);
        let f2 = make_finding("f2", "injection", "src-2", 2000);
        let results = correlator.correlate(&[&f1, &f2]).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_attribute_correlator_empty_category_skipped() {
        let correlator = AttributeCorrelator::new("attr-1", 1);
        let f1 = DetectionFinding::new("f1", "Test", SecuritySeverity::High, 1000);
        let results = correlator.correlate(&[&f1]).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_correlator_metadata() {
        let tw = TimeWindowCorrelator::new("tw-1", 100, 2);
        assert_eq!(tw.correlation_rule_id(), "tw-1");
        assert_eq!(tw.supported_correlation_types(), vec!["time-window"]);
        assert!(tw.is_active());

        let attr = AttributeCorrelator::new("attr-1", 2);
        assert_eq!(attr.correlation_rule_id(), "attr-1");
        assert_eq!(attr.supported_correlation_types(), vec!["attribute"]);
        assert!(attr.is_active());
    }

    #[test]
    fn test_correlator_deactivate() {
        let mut tw = TimeWindowCorrelator::new("tw-1", 100, 2);
        tw.deactivate();
        assert!(!tw.is_active());

        let mut attr = AttributeCorrelator::new("attr-1", 2);
        attr.deactivate();
        assert!(!attr.is_active());
    }

    #[test]
    fn test_correlation_result_eq() {
        let r1 = CorrelationResult::new("c1", vec!["f1".into()], "time-window", "0.900", "test");
        let r2 = CorrelationResult::new("c1", vec!["f1".into()], "time-window", "0.900", "test");
        assert_eq!(r1, r2);
    }
}
