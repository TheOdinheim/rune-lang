// ═══════════════════════════════════════════════════════════════════════
// Contradiction — detection of contradictions between outputs and facts.
//
// ContradictionDetector maintains a knowledge base of known facts and
// checks new statements against them for negation, numeric disagreement,
// and self-consistency using keyword overlap and negation indicators.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::TruthError;

// ── ContradictionType ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContradictionType {
    DirectNegation,
    NumericDisagreement,
    TemporalInconsistency,
    CategoricalConflict,
    LogicalInconsistency,
    FactualError,
    SelfContradiction,
}

impl fmt::Display for ContradictionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectNegation => f.write_str("direct-negation"),
            Self::NumericDisagreement => f.write_str("numeric-disagreement"),
            Self::TemporalInconsistency => f.write_str("temporal-inconsistency"),
            Self::CategoricalConflict => f.write_str("categorical-conflict"),
            Self::LogicalInconsistency => f.write_str("logical-inconsistency"),
            Self::FactualError => f.write_str("factual-error"),
            Self::SelfContradiction => f.write_str("self-contradiction"),
        }
    }
}

// ── ContradictionSeverity ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ContradictionSeverity {
    Minor = 0,
    Moderate = 1,
    Major = 2,
    Critical = 3,
}

impl fmt::Display for ContradictionSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Minor => f.write_str("minor"),
            Self::Moderate => f.write_str("moderate"),
            Self::Major => f.write_str("major"),
            Self::Critical => f.write_str("critical"),
        }
    }
}

// ── StatementSource ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StatementSource {
    ModelOutput { model_id: String },
    KnownFact { knowledge_base: String },
    ExpertAssertion { expert_id: String },
    PriorOutput { output_id: String },
    PolicyRule { policy_id: String },
    UserProvided,
}

impl fmt::Display for StatementSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModelOutput { model_id } => write!(f, "model:{model_id}"),
            Self::KnownFact { knowledge_base } => write!(f, "fact:{knowledge_base}"),
            Self::ExpertAssertion { expert_id } => write!(f, "expert:{expert_id}"),
            Self::PriorOutput { output_id } => write!(f, "prior:{output_id}"),
            Self::PolicyRule { policy_id } => write!(f, "policy:{policy_id}"),
            Self::UserProvided => f.write_str("user-provided"),
        }
    }
}

// ── Statement ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Statement {
    pub id: String,
    pub content: String,
    pub source: StatementSource,
    pub timestamp: i64,
    pub metadata: HashMap<String, String>,
}

impl Statement {
    pub fn new(
        id: impl Into<String>,
        content: impl Into<String>,
        source: StatementSource,
        timestamp: i64,
    ) -> Self {
        Self {
            id: id.into(),
            content: content.into(),
            source,
            timestamp,
            metadata: HashMap::new(),
        }
    }
}

// ── ResolutionType ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolutionType {
    StatementACorrected,
    StatementBCorrected,
    BothPartiallyCorrect,
    FalsePositive,
    Deferred,
}

impl fmt::Display for ResolutionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StatementACorrected => f.write_str("statement-a-corrected"),
            Self::StatementBCorrected => f.write_str("statement-b-corrected"),
            Self::BothPartiallyCorrect => f.write_str("both-partially-correct"),
            Self::FalsePositive => f.write_str("false-positive"),
            Self::Deferred => f.write_str("deferred"),
        }
    }
}

// ── ContradictionResolution ──────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ContradictionResolution {
    pub resolution_type: ResolutionType,
    pub resolved_by: String,
    pub resolved_at: i64,
    pub explanation: String,
    pub authoritative_statement: Option<String>,
}

// ── Contradiction ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Contradiction {
    pub id: String,
    pub statement_a: Statement,
    pub statement_b: Statement,
    pub contradiction_type: ContradictionType,
    pub severity: ContradictionSeverity,
    pub confidence: f64,
    pub detected_at: i64,
    pub resolution: Option<ContradictionResolution>,
}

// ── ContradictionDetector ────────────────────────────────────────────

pub struct ContradictionDetector {
    known_facts: Vec<Statement>,
    detected: Vec<Contradiction>,
    counter: u64,
    checks_performed: u64,
}

const NEGATION_WORDS: &[&str] = &[
    "not", "no", "never", "false", "incorrect", "wrong", "isn't", "doesn't", "won't", "cannot",
    "neither", "nor", "none",
];

impl ContradictionDetector {
    pub fn new() -> Self {
        Self {
            known_facts: Vec::new(),
            detected: Vec::new(),
            counter: 0,
            checks_performed: 0,
        }
    }

    pub fn add_known_fact(&mut self, content: &str, source: &str, timestamp: i64) {
        self.known_facts.push(Statement::new(
            format!("fact-{}", self.known_facts.len()),
            content,
            StatementSource::KnownFact {
                knowledge_base: source.into(),
            },
            timestamp,
        ));
    }

    pub fn check_against_facts(
        &mut self,
        statement: &Statement,
        now: i64,
    ) -> Vec<Contradiction> {
        let mut contradictions = Vec::new();
        for fact in &self.known_facts.clone() {
            self.checks_performed += 1;
            if let Some(c) = detect_contradiction(
                statement,
                fact,
                &mut self.counter,
                now,
            ) {
                contradictions.push(c);
            }
        }
        self.detected.extend(contradictions.clone());
        contradictions
    }

    pub fn check_pair(
        &mut self,
        a: &Statement,
        b: &Statement,
        now: i64,
    ) -> Option<Contradiction> {
        self.checks_performed += 1;
        let c = detect_contradiction(a, b, &mut self.counter, now);
        if let Some(ref contradiction) = c {
            self.detected.push(contradiction.clone());
        }
        c
    }

    pub fn check_self_consistency(
        &mut self,
        text: &str,
        source: StatementSource,
        now: i64,
    ) -> Vec<Contradiction> {
        let sentences: Vec<&str> = text
            .split(|c: char| c == '.' || c == '!' || c == '?')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        let mut contradictions = Vec::new();
        for i in 0..sentences.len() {
            for j in (i + 1)..sentences.len() {
                let a = Statement::new(
                    format!("self-{i}"),
                    sentences[i],
                    source.clone(),
                    now,
                );
                let b = Statement::new(
                    format!("self-{j}"),
                    sentences[j],
                    source.clone(),
                    now,
                );
                self.checks_performed += 1;
                if let Some(mut c) = detect_contradiction(&a, &b, &mut self.counter, now) {
                    c.contradiction_type = ContradictionType::SelfContradiction;
                    self.detected.push(c.clone());
                    contradictions.push(c);
                }
            }
        }
        contradictions
    }

    pub fn resolve(
        &mut self,
        contradiction_id: &str,
        resolution: ContradictionResolution,
    ) -> Result<(), TruthError> {
        let c = self
            .detected
            .iter_mut()
            .find(|c| c.id == contradiction_id)
            .ok_or_else(|| TruthError::ContradictionNotFound(contradiction_id.into()))?;
        if c.resolution.is_some() {
            return Err(TruthError::ContradictionAlreadyResolved(
                contradiction_id.into(),
            ));
        }
        c.resolution = Some(resolution);
        Ok(())
    }

    pub fn unresolved(&self) -> Vec<&Contradiction> {
        self.detected
            .iter()
            .filter(|c| c.resolution.is_none())
            .collect()
    }

    pub fn by_severity(&self, severity: ContradictionSeverity) -> Vec<&Contradiction> {
        self.detected
            .iter()
            .filter(|c| c.severity == severity)
            .collect()
    }

    pub fn contradiction_rate(&self) -> f64 {
        if self.checks_performed == 0 {
            return 0.0;
        }
        self.detected.len() as f64 / self.checks_performed as f64
    }

    pub fn count(&self) -> usize {
        self.detected.len()
    }

    pub fn fact_count(&self) -> usize {
        self.known_facts.len()
    }
}

impl Default for ContradictionDetector {
    fn default() -> Self {
        Self::new()
    }
}

fn tokenize(text: &str) -> Vec<String> {
    text.split_whitespace()
        .map(|w| w.to_lowercase().replace(|c: char| !c.is_alphanumeric(), ""))
        .filter(|w| !w.is_empty())
        .collect()
}

fn extract_numbers(tokens: &[String]) -> Vec<f64> {
    tokens
        .iter()
        .filter_map(|t| t.parse::<f64>().ok())
        .collect()
}

fn has_negation(tokens: &[String]) -> bool {
    tokens
        .iter()
        .any(|t| NEGATION_WORDS.contains(&t.as_str()))
}

fn key_terms(tokens: &[String]) -> HashSet<String> {
    // Approximate "key terms" as non-stopword tokens and capitalized words.
    let stopwords: HashSet<&str> = [
        "the", "a", "an", "is", "are", "was", "were", "be", "been", "being", "have", "has",
        "had", "do", "does", "did", "will", "would", "could", "should", "may", "might", "shall",
        "can", "of", "in", "to", "for", "with", "on", "at", "by", "from", "it", "its", "this",
        "that", "these", "those", "and", "or", "but", "if", "then", "than",
    ]
    .into_iter()
    .collect();
    tokens
        .iter()
        .filter(|t| !stopwords.contains(t.as_str()) && t.len() > 1)
        .cloned()
        .collect()
}

fn detect_contradiction(
    a: &Statement,
    b: &Statement,
    counter: &mut u64,
    now: i64,
) -> Option<Contradiction> {
    let tokens_a = tokenize(&a.content);
    let tokens_b = tokenize(&b.content);

    let keys_a = key_terms(&tokens_a);
    let keys_b = key_terms(&tokens_b);

    let shared: HashSet<_> = keys_a.intersection(&keys_b).collect();
    if shared.is_empty() {
        return None; // Different topics.
    }

    let overlap_ratio = shared.len() as f64 / keys_a.union(&keys_b).count().max(1) as f64;

    // Check for negation disagreement.
    let neg_a = has_negation(&tokens_a);
    let neg_b = has_negation(&tokens_b);

    if neg_a != neg_b && overlap_ratio > 0.2 {
        *counter += 1;
        let severity = if overlap_ratio > 0.5 {
            ContradictionSeverity::Major
        } else {
            ContradictionSeverity::Moderate
        };
        return Some(Contradiction {
            id: format!("contra-{counter}"),
            statement_a: a.clone(),
            statement_b: b.clone(),
            contradiction_type: ContradictionType::DirectNegation,
            severity,
            confidence: overlap_ratio.min(0.95),
            detected_at: now,
            resolution: None,
        });
    }

    // Check for numeric disagreement.
    let nums_a = extract_numbers(&tokens_a);
    let nums_b = extract_numbers(&tokens_b);

    if !nums_a.is_empty() && !nums_b.is_empty() && overlap_ratio > 0.2 {
        // Check if corresponding numbers differ significantly.
        for na in &nums_a {
            for nb in &nums_b {
                if na != nb {
                    let diff_ratio = (na - nb).abs() / na.abs().max(nb.abs()).max(1.0);
                    if diff_ratio > 0.1 {
                        *counter += 1;
                        return Some(Contradiction {
                            id: format!("contra-{counter}"),
                            statement_a: a.clone(),
                            statement_b: b.clone(),
                            contradiction_type: ContradictionType::NumericDisagreement,
                            severity: ContradictionSeverity::Moderate,
                            confidence: (overlap_ratio * 0.8).min(0.9),
                            detected_at: now,
                            resolution: None,
                        });
                    }
                }
            }
        }
    }

    None
}

// ═══════════════════════════════════════════════════════════════════════
// Layer 2: Enhanced Contradiction Detection
// ═══════════════════════════════════════════════════════════════════════

/// Value type for structured claims.
#[derive(Debug, Clone, PartialEq)]
pub enum ClaimValue {
    Boolean(bool),
    Numeric(f64),
    Text(String),
    Category(String),
}

/// A structured claim about a subject.
#[derive(Debug, Clone)]
pub struct Claim {
    pub id: String,
    pub source: String,
    pub subject: String,
    pub predicate: String,
    pub value: ClaimValue,
    pub confidence: f64,
    pub timestamp: i64,
    pub evidence: Vec<String>,
}

impl Claim {
    pub fn new(
        id: impl Into<String>,
        source: impl Into<String>,
        subject: impl Into<String>,
        predicate: impl Into<String>,
        value: ClaimValue,
        confidence: f64,
        timestamp: i64,
    ) -> Self {
        Self {
            id: id.into(),
            source: source.into(),
            subject: subject.into(),
            predicate: predicate.into(),
            value,
            confidence,
            timestamp,
            evidence: Vec::new(),
        }
    }
}

/// A detected contradiction between structured claims.
#[derive(Debug, Clone)]
pub struct ClaimContradiction {
    pub claim_a_id: String,
    pub claim_b_id: String,
    pub subject: String,
    pub predicate: String,
    pub value_a: ClaimValue,
    pub value_b: ClaimValue,
    pub contradiction_type: ClaimContradictionType,
    pub severity: ClaimContradictionSeverity,
}

/// Type of contradiction between claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimContradictionType {
    DirectOpposite,
    NumericDeviation { deviation_pct: u64 },
    CategoricalMismatch,
    TextualConflict,
}

/// Severity of a claim contradiction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClaimContradictionSeverity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// Store for structured claims with contradiction detection.
#[derive(Default)]
pub struct ClaimStore {
    pub claims: Vec<Claim>,
}

impl ClaimStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_claim(&mut self, claim: Claim) {
        self.claims.push(claim);
    }

    pub fn claims_about(&self, subject: &str) -> Vec<&Claim> {
        self.claims.iter().filter(|c| c.subject == subject).collect()
    }

    pub fn claims_by_source(&self, source: &str) -> Vec<&Claim> {
        self.claims.iter().filter(|c| c.source == source).collect()
    }

    pub fn detect_contradictions(&self) -> Vec<ClaimContradiction> {
        let mut contradictions = Vec::new();
        for i in 0..self.claims.len() {
            for j in (i + 1)..self.claims.len() {
                let a = &self.claims[i];
                let b = &self.claims[j];
                if a.subject == b.subject && a.predicate == b.predicate && a.value != b.value {
                    let (ctype, severity) = classify_claim_contradiction(a, b);
                    contradictions.push(ClaimContradiction {
                        claim_a_id: a.id.clone(),
                        claim_b_id: b.id.clone(),
                        subject: a.subject.clone(),
                        predicate: a.predicate.clone(),
                        value_a: a.value.clone(),
                        value_b: b.value.clone(),
                        contradiction_type: ctype,
                        severity,
                    });
                }
            }
        }
        contradictions
    }

    pub fn detect_contradictions_for(&self, subject: &str) -> Vec<ClaimContradiction> {
        self.detect_contradictions()
            .into_iter()
            .filter(|c| c.subject == subject)
            .collect()
    }
}

fn classify_claim_contradiction(a: &Claim, b: &Claim) -> (ClaimContradictionType, ClaimContradictionSeverity) {
    match (&a.value, &b.value) {
        (ClaimValue::Boolean(_), ClaimValue::Boolean(_)) => {
            let severity = if a.confidence > 0.8 && b.confidence > 0.8 {
                ClaimContradictionSeverity::Critical
            } else {
                ClaimContradictionSeverity::High
            };
            (ClaimContradictionType::DirectOpposite, severity)
        }
        (ClaimValue::Numeric(va), ClaimValue::Numeric(vb)) => {
            let max_abs = va.abs().max(vb.abs()).max(1.0);
            let deviation = ((va - vb).abs() / max_abs * 100.0) as u64;
            let severity = if deviation > 300 {
                ClaimContradictionSeverity::High
            } else {
                ClaimContradictionSeverity::Medium
            };
            (ClaimContradictionType::NumericDeviation { deviation_pct: deviation }, severity)
        }
        (ClaimValue::Category(_), ClaimValue::Category(_)) => {
            (ClaimContradictionType::CategoricalMismatch, ClaimContradictionSeverity::Medium)
        }
        _ => {
            (ClaimContradictionType::TextualConflict, ClaimContradictionSeverity::Low)
        }
    }
}

/// Strategy for resolving a contradiction.
#[derive(Debug, Clone)]
pub enum ClaimResolutionStrategy {
    HighestConfidence,
    MostRecent,
    SourcePriority { priority_order: Vec<String> },
    Consensus { required_agreement: f64 },
    ManualOverride,
}

/// Result of resolving a contradiction.
#[derive(Debug, Clone)]
pub struct ClaimConflictResolution {
    pub contradiction_subject: String,
    pub contradiction_predicate: String,
    pub resolution: ClaimResolutionStrategy,
    pub resolved_value: ClaimValue,
    pub resolved_by: String,
    pub resolved_at: i64,
    pub rationale: String,
}

/// Resolve a contradiction using the given strategy.
pub fn resolve_claim_contradiction(
    contradiction: &ClaimContradiction,
    claims: &[&Claim],
    strategy: &ClaimResolutionStrategy,
    now: i64,
) -> ClaimConflictResolution {
    let relevant: Vec<&&Claim> = claims.iter()
        .filter(|c| c.subject == contradiction.subject && c.predicate == contradiction.predicate)
        .collect();

    let (resolved_value, rationale) = match strategy {
        ClaimResolutionStrategy::HighestConfidence => {
            let best = relevant.iter()
                .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap())
                .unwrap();
            (best.value.clone(), format!("highest confidence: {:.2}", best.confidence))
        }
        ClaimResolutionStrategy::MostRecent => {
            let newest = relevant.iter()
                .max_by_key(|c| c.timestamp)
                .unwrap();
            (newest.value.clone(), format!("most recent: timestamp {}", newest.timestamp))
        }
        ClaimResolutionStrategy::SourcePriority { priority_order } => {
            let best = priority_order.iter()
                .find_map(|src| relevant.iter().find(|c| c.source == *src))
                .unwrap_or(relevant.first().unwrap());
            (best.value.clone(), format!("source priority: {}", best.source))
        }
        ClaimResolutionStrategy::Consensus { .. } | ClaimResolutionStrategy::ManualOverride => {
            // For consensus/manual, just pick the most common value or first
            (contradiction.value_a.clone(), "manual/consensus fallback".into())
        }
    };

    ClaimConflictResolution {
        contradiction_subject: contradiction.subject.clone(),
        contradiction_predicate: contradiction.predicate.clone(),
        resolution: strategy.clone(),
        resolved_value,
        resolved_by: "system".into(),
        resolved_at: now,
        rationale,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn model_statement(id: &str, content: &str) -> Statement {
        Statement::new(
            id,
            content,
            StatementSource::ModelOutput {
                model_id: "model-1".into(),
            },
            1000,
        )
    }

    #[test]
    fn test_add_known_fact_and_check() {
        let mut d = ContradictionDetector::new();
        d.add_known_fact("The earth is round", "geography", 1000);
        assert_eq!(d.fact_count(), 1);

        let stmt = model_statement("s1", "The earth is not round");
        let contradictions = d.check_against_facts(&stmt, 2000);
        assert!(!contradictions.is_empty());
    }

    #[test]
    fn test_direct_negation() {
        let mut d = ContradictionDetector::new();
        d.add_known_fact("Python is a programming language", "tech", 1000);
        let stmt = model_statement("s1", "Python is not a programming language");
        let contradictions = d.check_against_facts(&stmt, 2000);
        assert_eq!(contradictions.len(), 1);
        assert_eq!(
            contradictions[0].contradiction_type,
            ContradictionType::DirectNegation
        );
    }

    #[test]
    fn test_numeric_disagreement() {
        let mut d = ContradictionDetector::new();
        d.add_known_fact("The population is 1000 people", "census", 1000);
        let stmt = model_statement("s1", "The population is 5000 people");
        let contradictions = d.check_against_facts(&stmt, 2000);
        assert_eq!(contradictions.len(), 1);
        assert_eq!(
            contradictions[0].contradiction_type,
            ContradictionType::NumericDisagreement
        );
    }

    #[test]
    fn test_no_contradiction_when_agree() {
        let mut d = ContradictionDetector::new();
        d.add_known_fact("The sky is blue", "science", 1000);
        let stmt = model_statement("s1", "The sky is blue and clear");
        let contradictions = d.check_against_facts(&stmt, 2000);
        assert!(contradictions.is_empty());
    }

    #[test]
    fn test_no_contradiction_different_topics() {
        let mut d = ContradictionDetector::new();
        d.add_known_fact("Cats are mammals", "biology", 1000);
        let stmt = model_statement("s1", "JavaScript runs in browsers");
        let contradictions = d.check_against_facts(&stmt, 2000);
        assert!(contradictions.is_empty());
    }

    #[test]
    fn test_check_pair() {
        let mut d = ContradictionDetector::new();
        let a = model_statement("a", "The system is operational");
        let b = model_statement("b", "The system is not operational");
        let c = d.check_pair(&a, &b, 2000);
        assert!(c.is_some());
    }

    #[test]
    fn test_check_self_consistency() {
        let mut d = ContradictionDetector::new();
        let text = "The server is running. The server is not running.";
        let contradictions = d.check_self_consistency(
            text,
            StatementSource::ModelOutput {
                model_id: "m1".into(),
            },
            2000,
        );
        assert!(!contradictions.is_empty());
        assert_eq!(
            contradictions[0].contradiction_type,
            ContradictionType::SelfContradiction
        );
    }

    #[test]
    fn test_resolve() {
        let mut d = ContradictionDetector::new();
        d.add_known_fact("X is true", "facts", 1000);
        let stmt = model_statement("s1", "X is not true");
        d.check_against_facts(&stmt, 2000);
        let id = d.detected[0].id.clone();
        d.resolve(
            &id,
            ContradictionResolution {
                resolution_type: ResolutionType::StatementBCorrected,
                resolved_by: "alice".into(),
                resolved_at: 3000,
                explanation: "fact confirmed".into(),
                authoritative_statement: Some("X is true".into()),
            },
        )
        .unwrap();
        assert!(d.unresolved().is_empty());
    }

    #[test]
    fn test_unresolved() {
        let mut d = ContradictionDetector::new();
        d.add_known_fact("X is true", "facts", 1000);
        let stmt = model_statement("s1", "X is not true");
        d.check_against_facts(&stmt, 2000);
        assert_eq!(d.unresolved().len(), 1);
    }

    #[test]
    fn test_by_severity() {
        let mut d = ContradictionDetector::new();
        d.add_known_fact("X is true", "facts", 1000);
        let stmt = model_statement("s1", "X is not true");
        d.check_against_facts(&stmt, 2000);
        // The detected contradiction should be Moderate or Major
        let sev = d.detected[0].severity;
        assert_eq!(d.by_severity(sev).len(), 1);
    }

    #[test]
    fn test_contradiction_rate() {
        let mut d = ContradictionDetector::new();
        d.add_known_fact("X is true", "facts", 1000);
        let stmt1 = model_statement("s1", "X is not true");
        d.check_against_facts(&stmt1, 2000);
        let stmt2 = model_statement("s2", "Y is something else entirely");
        d.check_against_facts(&stmt2, 3000);
        // 1 contradiction found in 2 checks
        assert!((d.contradiction_rate() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_contradiction_type_display() {
        assert_eq!(ContradictionType::DirectNegation.to_string(), "direct-negation");
        assert_eq!(ContradictionType::NumericDisagreement.to_string(), "numeric-disagreement");
        assert_eq!(ContradictionType::TemporalInconsistency.to_string(), "temporal-inconsistency");
        assert_eq!(ContradictionType::CategoricalConflict.to_string(), "categorical-conflict");
        assert_eq!(ContradictionType::LogicalInconsistency.to_string(), "logical-inconsistency");
        assert_eq!(ContradictionType::FactualError.to_string(), "factual-error");
        assert_eq!(ContradictionType::SelfContradiction.to_string(), "self-contradiction");
    }

    #[test]
    fn test_contradiction_severity_ordering() {
        assert!(ContradictionSeverity::Minor < ContradictionSeverity::Moderate);
        assert!(ContradictionSeverity::Moderate < ContradictionSeverity::Major);
        assert!(ContradictionSeverity::Major < ContradictionSeverity::Critical);
    }

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_claim_store_boolean_conflict() {
        let mut store = ClaimStore::new();
        store.add_claim(Claim::new("c1", "source-a", "server", "is_running", ClaimValue::Boolean(true), 0.9, 1000));
        store.add_claim(Claim::new("c2", "source-b", "server", "is_running", ClaimValue::Boolean(false), 0.8, 2000));
        let contradictions = store.detect_contradictions();
        assert_eq!(contradictions.len(), 1);
        assert_eq!(contradictions[0].contradiction_type, ClaimContradictionType::DirectOpposite);
    }

    #[test]
    fn test_claim_store_numeric_deviation() {
        let mut store = ClaimStore::new();
        store.add_claim(Claim::new("c1", "src-a", "metric", "value", ClaimValue::Numeric(100.0), 0.9, 1000));
        store.add_claim(Claim::new("c2", "src-b", "metric", "value", ClaimValue::Numeric(500.0), 0.9, 2000));
        let contradictions = store.detect_contradictions();
        assert_eq!(contradictions.len(), 1);
        assert!(matches!(contradictions[0].contradiction_type, ClaimContradictionType::NumericDeviation { .. }));
    }

    #[test]
    fn test_claim_store_no_contradiction_consistent() {
        let mut store = ClaimStore::new();
        store.add_claim(Claim::new("c1", "src-a", "server", "is_running", ClaimValue::Boolean(true), 0.9, 1000));
        store.add_claim(Claim::new("c2", "src-b", "server", "is_running", ClaimValue::Boolean(true), 0.8, 2000));
        assert!(store.detect_contradictions().is_empty());
    }

    #[test]
    fn test_claim_contradiction_severity_direct_opposite() {
        let mut store = ClaimStore::new();
        store.add_claim(Claim::new("c1", "a", "x", "p", ClaimValue::Boolean(true), 0.95, 1000));
        store.add_claim(Claim::new("c2", "b", "x", "p", ClaimValue::Boolean(false), 0.95, 2000));
        let c = &store.detect_contradictions()[0];
        assert_eq!(c.severity, ClaimContradictionSeverity::Critical);
    }

    #[test]
    fn test_resolve_highest_confidence() {
        let mut store = ClaimStore::new();
        store.add_claim(Claim::new("c1", "a", "x", "val", ClaimValue::Numeric(10.0), 0.9, 1000));
        store.add_claim(Claim::new("c2", "b", "x", "val", ClaimValue::Numeric(20.0), 0.5, 2000));
        let contradictions = store.detect_contradictions();
        let claims_refs: Vec<&Claim> = store.claims.iter().collect();
        let resolution = resolve_claim_contradiction(
            &contradictions[0],
            &claims_refs,
            &ClaimResolutionStrategy::HighestConfidence,
            3000,
        );
        assert_eq!(resolution.resolved_value, ClaimValue::Numeric(10.0));
    }

    #[test]
    fn test_resolve_most_recent() {
        let mut store = ClaimStore::new();
        store.add_claim(Claim::new("c1", "a", "x", "val", ClaimValue::Numeric(10.0), 0.9, 1000));
        store.add_claim(Claim::new("c2", "b", "x", "val", ClaimValue::Numeric(20.0), 0.5, 2000));
        let contradictions = store.detect_contradictions();
        let claims_refs: Vec<&Claim> = store.claims.iter().collect();
        let resolution = resolve_claim_contradiction(
            &contradictions[0],
            &claims_refs,
            &ClaimResolutionStrategy::MostRecent,
            3000,
        );
        assert_eq!(resolution.resolved_value, ClaimValue::Numeric(20.0));
    }

    #[test]
    fn test_claim_store_claims_about() {
        let mut store = ClaimStore::new();
        store.add_claim(Claim::new("c1", "a", "server-1", "status", ClaimValue::Boolean(true), 0.9, 1000));
        store.add_claim(Claim::new("c2", "b", "server-2", "status", ClaimValue::Boolean(false), 0.8, 2000));
        assert_eq!(store.claims_about("server-1").len(), 1);
    }

    #[test]
    fn test_claim_store_claims_by_source() {
        let mut store = ClaimStore::new();
        store.add_claim(Claim::new("c1", "monitor-a", "x", "p", ClaimValue::Boolean(true), 0.9, 1000));
        store.add_claim(Claim::new("c2", "monitor-b", "x", "p", ClaimValue::Boolean(false), 0.8, 2000));
        assert_eq!(store.claims_by_source("monitor-a").len(), 1);
    }
}
