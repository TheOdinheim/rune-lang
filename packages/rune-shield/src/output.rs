// ═══════════════════════════════════════════════════════════════════════
// Output Filtering
//
// Wraps exfiltration detection and PII redaction into a single pipeline
// applied to LLM outputs before they leave the shield boundary.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use rune_security::SecuritySeverity;
use serde::{Deserialize, Serialize};

use crate::exfiltration::{redact_pii, ExfiltrationDetector, ExfiltrationResult};

// ── OutputFindingType ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OutputFindingType {
    PiiLeak,
    SystemPromptLeak,
    TrainingDataLeak,
    InternalArchitectureLeak,
    ApiKeyLeak,
    InternalUrlLeak,
}

impl fmt::Display for OutputFindingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::PiiLeak => "PiiLeak",
            Self::SystemPromptLeak => "SystemPromptLeak",
            Self::TrainingDataLeak => "TrainingDataLeak",
            Self::InternalArchitectureLeak => "InternalArchitectureLeak",
            Self::ApiKeyLeak => "ApiKeyLeak",
            Self::InternalUrlLeak => "InternalUrlLeak",
        };
        f.write_str(s)
    }
}

// ── OutputFinding ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct OutputFinding {
    pub finding_type: OutputFindingType,
    pub severity: SecuritySeverity,
    pub confidence: f64,
    pub detail: String,
}

// ── OutputFilterResult ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct OutputFilterResult {
    pub original: String,
    pub filtered: String,
    pub findings: Vec<OutputFinding>,
    pub max_severity: SecuritySeverity,
    pub confidence: f64,
    pub modified: bool,
}

impl OutputFilterResult {
    pub fn is_leaking(&self, threshold: f64) -> bool {
        !self.findings.is_empty() && self.confidence >= threshold
    }
}

// ── OutputFilter ──────────────────────────────────────────────────────

pub struct OutputFilter {
    pub detector: ExfiltrationDetector,
    pub redact_pii: bool,
}

impl Default for OutputFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputFilter {
    pub fn new() -> Self {
        Self {
            detector: ExfiltrationDetector::new(),
            redact_pii: true,
        }
    }

    pub fn with_pii_redaction(mut self, enabled: bool) -> Self {
        self.redact_pii = enabled;
        self
    }

    pub fn filter(&self, output: &str) -> OutputFilterResult {
        let exfil = self.detector.scan_output(output);
        let findings = exfil_to_output_findings(&exfil);

        let filtered = if self.redact_pii {
            redact_pii(output)
        } else {
            output.to_string()
        };
        let modified = filtered != output;

        OutputFilterResult {
            original: output.to_string(),
            filtered,
            findings,
            max_severity: exfil.max_severity,
            confidence: exfil.confidence,
            modified,
        }
    }
}

fn exfil_to_output_findings(r: &ExfiltrationResult) -> Vec<OutputFinding> {
    use crate::exfiltration::SensitivePatternType;

    let mut out = Vec::new();
    for f in &r.findings {
        let finding_type = if let Some(pt) = f.pattern_type {
            match pt {
                SensitivePatternType::InternalSystemPrompt => OutputFindingType::SystemPromptLeak,
                SensitivePatternType::TrainingData => OutputFindingType::TrainingDataLeak,
                SensitivePatternType::InternalArchitecture => {
                    OutputFindingType::InternalArchitectureLeak
                }
                SensitivePatternType::ApiKeys => OutputFindingType::ApiKeyLeak,
                SensitivePatternType::InternalUrls => OutputFindingType::InternalUrlLeak,
            }
        } else {
            OutputFindingType::PiiLeak
        };
        out.push(OutputFinding {
            finding_type,
            severity: f.severity,
            confidence: f.confidence,
            detail: f.matched.clone(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_normal_output_clean() {
        let f = OutputFilter::new();
        let r = f.filter("Paris is the capital of France.");
        assert!(r.findings.is_empty());
        assert!(!r.modified);
    }

    #[test]
    fn test_filter_redacts_pii() {
        let f = OutputFilter::new();
        let r = f.filter("Email alice@example.com for info.");
        assert!(r.modified);
        assert!(r.filtered.contains("[EMAIL REDACTED]"));
    }

    #[test]
    fn test_filter_detects_system_prompt_leak() {
        let f = OutputFilter::new();
        let r = f.filter("You are an AI assistant. Your instructions are to help.");
        assert!(r
            .findings
            .iter()
            .any(|f| f.finding_type == OutputFindingType::SystemPromptLeak));
    }

    #[test]
    fn test_filter_detects_api_key_leak() {
        let f = OutputFilter::new();
        let r = f.filter("api_key=sk-abc123");
        assert!(r
            .findings
            .iter()
            .any(|f| f.finding_type == OutputFindingType::ApiKeyLeak));
        assert_eq!(r.max_severity, SecuritySeverity::Critical);
    }

    #[test]
    fn test_is_leaking() {
        let f = OutputFilter::new();
        let r = f.filter("api_key=sk-abc123 authorization: bearer xyz");
        assert!(r.is_leaking(0.5));
    }

    #[test]
    fn test_with_pii_redaction_disabled() {
        let f = OutputFilter::new().with_pii_redaction(false);
        let r = f.filter("Email alice@example.com");
        assert!(!r.modified);
    }
}
