// ═══════════════════════════════════════════════════════════════════════
// Anonymization Techniques
//
// Mathematical anonymization: redaction, masking, generalization,
// hashing, pseudonymization, noise, k-anonymity, l-diversity, t-closeness.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet};
use std::fmt;

use rune_lang::stdlib::crypto::hash::sha3_256_hex;
use rune_lang::stdlib::crypto::sign::hmac_sha3_256;

// ── AnonymizationMethod ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum AnonymizationMethod {
    Redaction,
    Masking { visible_chars: usize, mask_char: char },
    Generalization { level: u32 },
    Hashing { salt: Option<String> },
    Pseudonymization { key_id: String },
    Noise { epsilon: f64 },
    Bucketing { bucket_size: u64 },
    Suppression,
    Swapping,
}

impl fmt::Display for AnonymizationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Redaction => write!(f, "Redaction"),
            Self::Masking { visible_chars, mask_char } => {
                write!(f, "Masking(visible={visible_chars}, mask='{mask_char}')")
            }
            Self::Generalization { level } => write!(f, "Generalization(level={level})"),
            Self::Hashing { salt } => {
                if salt.is_some() {
                    write!(f, "Hashing(salted)")
                } else {
                    write!(f, "Hashing")
                }
            }
            Self::Pseudonymization { key_id } => write!(f, "Pseudonymization({key_id})"),
            Self::Noise { epsilon } => write!(f, "Noise(ε={epsilon})"),
            Self::Bucketing { bucket_size } => write!(f, "Bucketing({bucket_size})"),
            Self::Suppression => write!(f, "Suppression"),
            Self::Swapping => write!(f, "Swapping"),
        }
    }
}

// ── Primitive functions ───────────────────────────────────────────────

pub fn redact(_value: &str) -> String {
    "[REDACTED]".into()
}

pub fn mask(value: &str, visible_start: usize, visible_end: usize, mask_char: char) -> String {
    let chars: Vec<char> = value.chars().collect();
    let n = chars.len();
    if visible_start + visible_end >= n {
        return value.to_string();
    }
    let mut out = String::with_capacity(n);
    for (i, c) in chars.iter().enumerate() {
        if i < visible_start || i >= n - visible_end {
            out.push(*c);
        } else {
            out.push(mask_char);
        }
    }
    out
}

pub fn generalize_number(value: i64, bucket_size: i64) -> String {
    if bucket_size <= 0 {
        return value.to_string();
    }
    // Handle negative values by flooring toward -infinity
    let lower = if value >= 0 {
        (value / bucket_size) * bucket_size
    } else {
        ((value - bucket_size + 1) / bucket_size) * bucket_size
    };
    let upper = lower + bucket_size - 1;
    format!("{lower}-{upper}")
}

pub fn hash_value(value: &str, salt: Option<&str>) -> String {
    let mut data = Vec::new();
    if let Some(s) = salt {
        data.extend_from_slice(s.as_bytes());
    }
    data.extend_from_slice(value.as_bytes());
    sha3_256_hex(&data)
}

pub fn pseudonymize(value: &str, key: &[u8]) -> String {
    hex::encode(hmac_sha3_256(key, value.as_bytes()))
}

// ── Noise mechanisms ──────────────────────────────────────────────────

/// Deterministic pseudo-random number in [0, 1) derived from a seed.
pub(crate) fn deterministic_uniform(seed: u64) -> f64 {
    // SplitMix64 step
    let mut z = seed.wrapping_add(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^= z >> 31;
    // Map to [0, 1) using top 53 bits
    (z >> 11) as f64 / (1u64 << 53) as f64
}

pub(crate) fn seed_from_value(value: f64) -> u64 {
    value.to_bits() ^ 0xDEADBEEFCAFEBABE
}

pub fn add_laplace_noise(value: f64, sensitivity: f64, epsilon: f64) -> f64 {
    if epsilon <= 0.0 {
        return value;
    }
    let scale = sensitivity / epsilon;
    // Sample Laplace: U ~ Uniform(-0.5, 0.5); X = -scale * sign(U) * ln(1 - 2|U|)
    let u = deterministic_uniform(seed_from_value(value)) - 0.5;
    let sign = if u < 0.0 { -1.0 } else { 1.0 };
    let abs_u = u.abs();
    // Avoid ln(0)
    let inner = (1.0 - 2.0 * abs_u).max(1e-12);
    let noise = -scale * sign * inner.ln();
    value + noise
}

pub fn add_gaussian_noise(value: f64, sensitivity: f64, epsilon: f64, delta: f64) -> f64 {
    if epsilon <= 0.0 || delta <= 0.0 {
        return value;
    }
    let sigma = sensitivity * (2.0 * (1.25_f64 / delta).ln()).sqrt() / epsilon;
    // Box-Muller from two deterministic uniforms
    let seed = seed_from_value(value);
    let u1 = deterministic_uniform(seed).max(1e-12);
    let u2 = deterministic_uniform(seed.wrapping_add(1));
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    value + z * sigma
}

// ── K-Anonymity ───────────────────────────────────────────────────────

pub struct KAnonymityChecker {
    pub quasi_identifiers: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct KAnonymityResult {
    pub satisfied: bool,
    pub k: usize,
    pub total_groups: usize,
    pub violating_groups: usize,
    pub smallest_group_size: usize,
    pub largest_group_size: usize,
}

impl KAnonymityChecker {
    pub fn new(quasi_identifiers: Vec<String>) -> Self {
        Self { quasi_identifiers }
    }

    pub fn check(&self, records: &[HashMap<String, String>], k: usize) -> KAnonymityResult {
        let groups = group_by_qi(records, &self.quasi_identifiers);
        if groups.is_empty() {
            return KAnonymityResult {
                satisfied: k == 0,
                k,
                total_groups: 0,
                violating_groups: 0,
                smallest_group_size: 0,
                largest_group_size: 0,
            };
        }
        let sizes: Vec<usize> = groups.values().map(|v| v.len()).collect();
        let violating = sizes.iter().filter(|&&s| s < k).count();
        KAnonymityResult {
            satisfied: violating == 0,
            k,
            total_groups: groups.len(),
            violating_groups: violating,
            smallest_group_size: *sizes.iter().min().unwrap(),
            largest_group_size: *sizes.iter().max().unwrap(),
        }
    }
}

// ── L-Diversity ───────────────────────────────────────────────────────

pub struct LDiversityChecker {
    pub quasi_identifiers: Vec<String>,
    pub sensitive_attribute: String,
}

#[derive(Debug, Clone)]
pub struct LDiversityResult {
    pub satisfied: bool,
    pub l: usize,
    pub total_groups: usize,
    pub violating_groups: usize,
    pub min_diversity: usize,
}

impl LDiversityChecker {
    pub fn new(quasi_identifiers: Vec<String>, sensitive_attribute: String) -> Self {
        Self { quasi_identifiers, sensitive_attribute }
    }

    pub fn check(&self, records: &[HashMap<String, String>], l: usize) -> LDiversityResult {
        let groups = group_by_qi(records, &self.quasi_identifiers);
        if groups.is_empty() {
            return LDiversityResult {
                satisfied: l == 0,
                l,
                total_groups: 0,
                violating_groups: 0,
                min_diversity: 0,
            };
        }
        let mut diversities = Vec::new();
        let mut violating = 0;
        for group in groups.values() {
            let distinct: HashSet<String> = group
                .iter()
                .filter_map(|idx| records[*idx].get(&self.sensitive_attribute).cloned())
                .collect();
            if distinct.len() < l {
                violating += 1;
            }
            diversities.push(distinct.len());
        }
        LDiversityResult {
            satisfied: violating == 0,
            l,
            total_groups: groups.len(),
            violating_groups: violating,
            min_diversity: *diversities.iter().min().unwrap_or(&0),
        }
    }
}

// ── T-Closeness ───────────────────────────────────────────────────────

pub struct TClosenessChecker {
    pub quasi_identifiers: Vec<String>,
    pub sensitive_attribute: String,
}

#[derive(Debug, Clone)]
pub struct TClosenessResult {
    pub satisfied: bool,
    pub t_threshold: f64,
    pub max_distance: f64,
    pub violating_groups: usize,
}

impl TClosenessChecker {
    pub fn new(quasi_identifiers: Vec<String>, sensitive_attribute: String) -> Self {
        Self { quasi_identifiers, sensitive_attribute }
    }

    pub fn check(&self, records: &[HashMap<String, String>], t: f64) -> TClosenessResult {
        let groups = group_by_qi(records, &self.quasi_identifiers);
        let overall = distribution(
            records.iter().enumerate().map(|(i, _)| i).collect::<Vec<_>>(),
            records,
            &self.sensitive_attribute,
        );
        let mut max_dist: f64 = 0.0;
        let mut violating = 0;
        for group in groups.values() {
            let local = distribution(group.clone(), records, &self.sensitive_attribute);
            let dist = emd_distance(&overall, &local);
            if dist > t {
                violating += 1;
            }
            if dist > max_dist {
                max_dist = dist;
            }
        }
        TClosenessResult {
            satisfied: violating == 0,
            t_threshold: t,
            max_distance: max_dist,
            violating_groups: violating,
        }
    }
}

fn group_by_qi(
    records: &[HashMap<String, String>],
    qis: &[String],
) -> HashMap<String, Vec<usize>> {
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, r) in records.iter().enumerate() {
        let key: Vec<String> = qis.iter().map(|q| r.get(q).cloned().unwrap_or_default()).collect();
        groups.entry(key.join("|")).or_default().push(i);
    }
    groups
}

fn distribution(
    indices: Vec<usize>,
    records: &[HashMap<String, String>],
    attr: &str,
) -> HashMap<String, f64> {
    if indices.is_empty() {
        return HashMap::new();
    }
    let n = indices.len() as f64;
    let mut counts: HashMap<String, f64> = HashMap::new();
    for i in indices {
        if let Some(v) = records[i].get(attr) {
            *counts.entry(v.clone()).or_insert(0.0) += 1.0;
        }
    }
    for v in counts.values_mut() {
        *v /= n;
    }
    counts
}

fn emd_distance(a: &HashMap<String, f64>, b: &HashMap<String, f64>) -> f64 {
    // Sum of absolute differences (total variation distance, upper bound on EMD for categorical)
    let mut keys: HashSet<&String> = HashSet::new();
    keys.extend(a.keys());
    keys.extend(b.keys());
    let mut sum = 0.0;
    for k in keys {
        let av = a.get(k).copied().unwrap_or(0.0);
        let bv = b.get(k).copied().unwrap_or(0.0);
        sum += (av - bv).abs();
    }
    sum / 2.0
}

// ── Pipeline ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AnonymizationStep {
    pub field: String,
    pub method: AnonymizationMethod,
    pub condition: Option<String>,
}

#[derive(Default)]
pub struct AnonymizationPipeline {
    pub steps: Vec<AnonymizationStep>,
}

impl AnonymizationPipeline {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_step(&mut self, step: AnonymizationStep) -> &mut Self {
        self.steps.push(step);
        self
    }

    pub fn apply(&self, record: &HashMap<String, String>) -> HashMap<String, String> {
        let mut out = record.clone();
        for step in &self.steps {
            if let Some(val) = out.get(&step.field).cloned() {
                let new_val = apply_method(&val, &step.method);
                if matches!(step.method, AnonymizationMethod::Suppression) {
                    out.remove(&step.field);
                } else {
                    out.insert(step.field.clone(), new_val);
                }
            }
        }
        out
    }

    pub fn apply_batch(
        &self,
        records: &[HashMap<String, String>],
    ) -> Vec<HashMap<String, String>> {
        records.iter().map(|r| self.apply(r)).collect()
    }
}

fn apply_method(value: &str, method: &AnonymizationMethod) -> String {
    match method {
        AnonymizationMethod::Redaction => redact(value),
        AnonymizationMethod::Masking { visible_chars, mask_char } => {
            mask(value, *visible_chars, 0, *mask_char)
        }
        AnonymizationMethod::Generalization { level } => {
            if let Ok(n) = value.parse::<i64>() {
                generalize_number(n, 10_i64.pow(*level))
            } else {
                format!("{value}*")
            }
        }
        AnonymizationMethod::Hashing { salt } => hash_value(value, salt.as_deref()),
        AnonymizationMethod::Pseudonymization { key_id } => {
            pseudonymize(value, key_id.as_bytes())
        }
        AnonymizationMethod::Noise { epsilon } => {
            if let Ok(n) = value.parse::<f64>() {
                format!("{:.4}", add_laplace_noise(n, 1.0, *epsilon))
            } else {
                value.to_string()
            }
        }
        AnonymizationMethod::Bucketing { bucket_size } => {
            if let Ok(n) = value.parse::<i64>() {
                generalize_number(n, *bucket_size as i64)
            } else {
                value.to_string()
            }
        }
        AnonymizationMethod::Suppression => String::new(),
        AnonymizationMethod::Swapping => value.to_string(),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Layer 2: Anonymization Hardening
// ═══════════════════════════════════════════════════════════════════════

use serde::{Deserialize, Serialize};

/// A group of records sharing the same quasi-identifier values.
#[derive(Debug, Clone)]
pub struct AnonymizationGroup {
    pub quasi_identifier_values: HashMap<String, String>,
    pub sensitive_values: Vec<String>,
    pub count: usize,
}

/// Standalone l-diversity check across pre-built groups.
pub fn check_l_diversity(groups: &[AnonymizationGroup], l: usize) -> LDiversityResult {
    if groups.is_empty() {
        return LDiversityResult {
            satisfied: l == 0,
            l,
            total_groups: 0,
            violating_groups: 0,
            min_diversity: 0,
        };
    }
    let mut min_div = usize::MAX;
    let mut violating = 0;
    for group in groups {
        let distinct: HashSet<&String> = group.sensitive_values.iter().collect();
        let d = distinct.len();
        if d < l {
            violating += 1;
        }
        if d < min_div {
            min_div = d;
        }
    }
    LDiversityResult {
        satisfied: violating == 0,
        l,
        total_groups: groups.len(),
        violating_groups: violating,
        min_diversity: min_div,
    }
}

/// Standalone t-closeness check across pre-built groups using EMD.
pub fn check_t_closeness(groups: &[AnonymizationGroup], t: f64) -> TClosenessResult {
    if groups.is_empty() {
        return TClosenessResult {
            satisfied: true,
            t_threshold: t,
            max_distance: 0.0,
            violating_groups: 0,
        };
    }
    // Build overall distribution from all groups
    let mut overall_counts: HashMap<String, f64> = HashMap::new();
    let mut total = 0usize;
    for group in groups {
        for val in &group.sensitive_values {
            *overall_counts.entry(val.clone()).or_insert(0.0) += 1.0;
            total += 1;
        }
    }
    if total > 0 {
        for v in overall_counts.values_mut() {
            *v /= total as f64;
        }
    }

    let mut max_dist: f64 = 0.0;
    let mut violating = 0;
    for group in groups {
        let n = group.sensitive_values.len();
        if n == 0 {
            continue;
        }
        let mut local: HashMap<String, f64> = HashMap::new();
        for val in &group.sensitive_values {
            *local.entry(val.clone()).or_insert(0.0) += 1.0;
        }
        for v in local.values_mut() {
            *v /= n as f64;
        }
        let dist = emd_distance(&overall_counts, &local);
        if dist > t {
            violating += 1;
        }
        if dist > max_dist {
            max_dist = dist;
        }
    }
    TClosenessResult {
        satisfied: violating == 0,
        t_threshold: t,
        max_distance: max_dist,
        violating_groups: violating,
    }
}

/// Risk level for re-identification assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Negligible,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Re-identification risk assessment result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReidentificationRisk {
    pub risk_level: RiskLevel,
    pub score: f64,
    pub smallest_group: usize,
    pub unique_records: usize,
    pub total_records: usize,
    pub recommendations: Vec<String>,
}

/// Assess re-identification risk from quasi-identifier groups.
pub fn reidentification_risk(
    records: &[HashMap<String, String>],
    quasi_identifiers: &[String],
) -> ReidentificationRisk {
    let groups = group_by_qi(records, quasi_identifiers);
    let total = records.len();
    if total == 0 {
        return ReidentificationRisk {
            risk_level: RiskLevel::Negligible,
            score: 0.0,
            smallest_group: 0,
            unique_records: 0,
            total_records: 0,
            recommendations: Vec::new(),
        };
    }
    let sizes: Vec<usize> = groups.values().map(|v| v.len()).collect();
    let smallest = *sizes.iter().min().unwrap_or(&0);
    let unique = sizes.iter().filter(|&&s| s == 1).count();
    let uniqueness_ratio = unique as f64 / total as f64;

    // Score: higher = more risk. Based on uniqueness ratio and smallest group.
    let score = if smallest == 0 {
        0.0
    } else {
        (uniqueness_ratio * 0.6 + (1.0 / smallest as f64) * 0.4).min(1.0)
    };

    let risk_level = if score < 0.05 {
        RiskLevel::Negligible
    } else if score < 0.2 {
        RiskLevel::Low
    } else if score < 0.5 {
        RiskLevel::Medium
    } else if score < 0.8 {
        RiskLevel::High
    } else {
        RiskLevel::Critical
    };

    let mut recommendations = Vec::new();
    if smallest < 5 {
        recommendations.push("Increase k-anonymity to at least k=5".into());
    }
    if uniqueness_ratio > 0.1 {
        recommendations.push("Generalize quasi-identifiers to reduce uniqueness".into());
    }
    if score > 0.5 {
        recommendations.push("Apply differential privacy or suppress small groups".into());
    }

    ReidentificationRisk {
        risk_level,
        score,
        smallest_group: smallest,
        unique_records: unique,
        total_records: total,
        recommendations,
    }
}

/// Generalization hierarchy for progressive data generalization.
pub struct GeneralizationHierarchy {
    pub name: String,
    levels: Vec<Box<dyn Fn(&str) -> String + Send + Sync>>,
}

impl fmt::Debug for GeneralizationHierarchy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneralizationHierarchy")
            .field("name", &self.name)
            .field("levels", &self.levels.len())
            .finish()
    }
}

impl GeneralizationHierarchy {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            levels: Vec::new(),
        }
    }

    pub fn add_level(&mut self, f: impl Fn(&str) -> String + Send + Sync + 'static) -> &mut Self {
        self.levels.push(Box::new(f));
        self
    }

    pub fn generalize(&self, value: &str, level: usize) -> String {
        if level == 0 || level > self.levels.len() {
            return value.to_string();
        }
        (self.levels[level - 1])(value)
    }

    pub fn max_level(&self) -> usize {
        self.levels.len()
    }

    /// Built-in age hierarchy: level 1 → 5-year bucket, level 2 → 10-year bucket, level 3 → "*"
    pub fn age() -> Self {
        let mut h = Self::new("age");
        h.add_level(|v| {
            if let Ok(n) = v.parse::<i64>() {
                let lower = (n / 5) * 5;
                format!("{}-{}", lower, lower + 4)
            } else {
                v.to_string()
            }
        });
        h.add_level(|v| {
            if let Ok(n) = v.parse::<i64>() {
                let lower = (n / 10) * 10;
                format!("{}-{}", lower, lower + 9)
            } else {
                v.to_string()
            }
        });
        h.add_level(|_| "*".to_string());
        h
    }

    /// Built-in ZIP hierarchy: level 1 → first 3 digits + "**", level 2 → first 1 digit + "****", level 3 → "*****"
    pub fn zip_code() -> Self {
        let mut h = Self::new("zip_code");
        h.add_level(|v| {
            if v.len() >= 3 {
                format!("{}**", &v[..3])
            } else {
                v.to_string()
            }
        });
        h.add_level(|v| {
            if !v.is_empty() {
                format!("{}****", &v[..1])
            } else {
                v.to_string()
            }
        });
        h.add_level(|_| "*****".to_string());
        h
    }

    /// Built-in date hierarchy: level 1 → year-month, level 2 → year, level 3 → "*"
    pub fn date() -> Self {
        let mut h = Self::new("date");
        h.add_level(|v| {
            // "2024-03-15" → "2024-03"
            if v.len() >= 7 {
                v[..7].to_string()
            } else {
                v.to_string()
            }
        });
        h.add_level(|v| {
            // "2024-03-15" → "2024"
            if v.len() >= 4 {
                v[..4].to_string()
            } else {
                v.to_string()
            }
        });
        h.add_level(|_| "*".to_string());
        h
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact() {
        assert_eq!(redact("sensitive"), "[REDACTED]");
    }

    #[test]
    fn test_mask_partial() {
        assert_eq!(mask("1234567890", 2, 4, '*'), "12****7890");
    }

    #[test]
    fn test_mask_full_visibility() {
        assert_eq!(mask("abc", 3, 3, '*'), "abc");
    }

    #[test]
    fn test_generalize_number() {
        assert_eq!(generalize_number(34, 10), "30-39");
        assert_eq!(generalize_number(156, 100), "100-199");
        assert_eq!(generalize_number(7, 10), "0-9");
    }

    #[test]
    fn test_hash_value_deterministic() {
        let a = hash_value("alice", None);
        let b = hash_value("alice", None);
        assert_eq!(a, b);
    }

    #[test]
    fn test_hash_value_different_salts() {
        let a = hash_value("alice", Some("s1"));
        let b = hash_value("alice", Some("s2"));
        assert_ne!(a, b);
    }

    #[test]
    fn test_pseudonymize_deterministic() {
        let key = b"my-key";
        assert_eq!(pseudonymize("alice", key), pseudonymize("alice", key));
    }

    #[test]
    fn test_pseudonymize_different_keys() {
        let a = pseudonymize("alice", b"k1");
        let b = pseudonymize("alice", b"k2");
        assert_ne!(a, b);
    }

    #[test]
    fn test_laplace_noise_changes_value() {
        let noisy = add_laplace_noise(100.0, 1.0, 0.5);
        assert!((noisy - 100.0).abs() > 0.0);
    }

    #[test]
    fn test_laplace_noise_large_epsilon_small_noise() {
        let noisy = add_laplace_noise(100.0, 1.0, 1000.0);
        assert!((noisy - 100.0).abs() < 1.0);
    }

    fn make_record(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn test_k_anonymity_satisfied() {
        let records = vec![
            make_record(&[("zip", "10001"), ("age", "30")]),
            make_record(&[("zip", "10001"), ("age", "30")]),
            make_record(&[("zip", "10002"), ("age", "40")]),
            make_record(&[("zip", "10002"), ("age", "40")]),
        ];
        let checker = KAnonymityChecker::new(vec!["zip".into(), "age".into()]);
        let result = checker.check(&records, 2);
        assert!(result.satisfied);
    }

    #[test]
    fn test_k_anonymity_violated() {
        let records = vec![
            make_record(&[("zip", "10001"), ("age", "30")]),
            make_record(&[("zip", "10002"), ("age", "40")]),
        ];
        let checker = KAnonymityChecker::new(vec!["zip".into(), "age".into()]);
        let result = checker.check(&records, 2);
        assert!(!result.satisfied);
        assert_eq!(result.violating_groups, 2);
    }

    #[test]
    fn test_l_diversity_satisfied() {
        let records = vec![
            make_record(&[("zip", "10001"), ("disease", "flu")]),
            make_record(&[("zip", "10001"), ("disease", "cold")]),
            make_record(&[("zip", "10002"), ("disease", "flu")]),
            make_record(&[("zip", "10002"), ("disease", "cold")]),
        ];
        let checker = LDiversityChecker::new(vec!["zip".into()], "disease".into());
        let result = checker.check(&records, 2);
        assert!(result.satisfied);
    }

    #[test]
    fn test_l_diversity_violated() {
        let records = vec![
            make_record(&[("zip", "10001"), ("disease", "flu")]),
            make_record(&[("zip", "10001"), ("disease", "flu")]),
        ];
        let checker = LDiversityChecker::new(vec!["zip".into()], "disease".into());
        let result = checker.check(&records, 2);
        assert!(!result.satisfied);
    }

    #[test]
    fn test_t_closeness_satisfied() {
        let records = vec![
            make_record(&[("zip", "10001"), ("disease", "flu")]),
            make_record(&[("zip", "10001"), ("disease", "cold")]),
            make_record(&[("zip", "10002"), ("disease", "flu")]),
            make_record(&[("zip", "10002"), ("disease", "cold")]),
        ];
        let checker = TClosenessChecker::new(vec!["zip".into()], "disease".into());
        let result = checker.check(&records, 0.5);
        assert!(result.satisfied);
    }

    #[test]
    fn test_t_closeness_violated() {
        let records = vec![
            make_record(&[("zip", "10001"), ("disease", "flu")]),
            make_record(&[("zip", "10001"), ("disease", "flu")]),
            make_record(&[("zip", "10002"), ("disease", "cold")]),
            make_record(&[("zip", "10002"), ("disease", "cold")]),
        ];
        let checker = TClosenessChecker::new(vec!["zip".into()], "disease".into());
        let result = checker.check(&records, 0.1);
        assert!(!result.satisfied);
    }

    #[test]
    fn test_pipeline_applies_steps() {
        let mut pipeline = AnonymizationPipeline::new();
        pipeline.add_step(AnonymizationStep {
            field: "name".into(),
            method: AnonymizationMethod::Redaction,
            condition: None,
        });
        pipeline.add_step(AnonymizationStep {
            field: "age".into(),
            method: AnonymizationMethod::Bucketing { bucket_size: 10 },
            condition: None,
        });
        let record = make_record(&[("name", "Alice"), ("age", "34")]);
        let out = pipeline.apply(&record);
        assert_eq!(out.get("name").unwrap(), "[REDACTED]");
        assert_eq!(out.get("age").unwrap(), "30-39");
    }

    #[test]
    fn test_pipeline_batch() {
        let mut pipeline = AnonymizationPipeline::new();
        pipeline.add_step(AnonymizationStep {
            field: "name".into(),
            method: AnonymizationMethod::Redaction,
            condition: None,
        });
        let records = vec![
            make_record(&[("name", "Alice")]),
            make_record(&[("name", "Bob")]),
        ];
        let out = pipeline.apply_batch(&records);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].get("name").unwrap(), "[REDACTED]");
    }

    #[test]
    fn test_anonymization_method_display() {
        assert_eq!(AnonymizationMethod::Redaction.to_string(), "Redaction");
        assert_eq!(
            AnonymizationMethod::Bucketing { bucket_size: 10 }.to_string(),
            "Bucketing(10)"
        );
    }

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_check_l_diversity_standalone_satisfied() {
        let groups = vec![
            AnonymizationGroup {
                quasi_identifier_values: [("zip".into(), "10001".into())].into(),
                sensitive_values: vec!["flu".into(), "cold".into(), "asthma".into()],
                count: 3,
            },
            AnonymizationGroup {
                quasi_identifier_values: [("zip".into(), "10002".into())].into(),
                sensitive_values: vec!["flu".into(), "cold".into()],
                count: 2,
            },
        ];
        let result = check_l_diversity(&groups, 2);
        assert!(result.satisfied);
        assert_eq!(result.min_diversity, 2);
    }

    #[test]
    fn test_check_l_diversity_standalone_violated() {
        let groups = vec![AnonymizationGroup {
            quasi_identifier_values: [("zip".into(), "10001".into())].into(),
            sensitive_values: vec!["flu".into(), "flu".into()],
            count: 2,
        }];
        let result = check_l_diversity(&groups, 2);
        assert!(!result.satisfied);
        assert_eq!(result.violating_groups, 1);
    }

    #[test]
    fn test_check_t_closeness_standalone_satisfied() {
        let groups = vec![
            AnonymizationGroup {
                quasi_identifier_values: [("zip".into(), "10001".into())].into(),
                sensitive_values: vec!["flu".into(), "cold".into()],
                count: 2,
            },
            AnonymizationGroup {
                quasi_identifier_values: [("zip".into(), "10002".into())].into(),
                sensitive_values: vec!["flu".into(), "cold".into()],
                count: 2,
            },
        ];
        let result = check_t_closeness(&groups, 0.5);
        assert!(result.satisfied);
    }

    #[test]
    fn test_check_t_closeness_standalone_violated() {
        let groups = vec![
            AnonymizationGroup {
                quasi_identifier_values: [("zip".into(), "10001".into())].into(),
                sensitive_values: vec!["flu".into(), "flu".into()],
                count: 2,
            },
            AnonymizationGroup {
                quasi_identifier_values: [("zip".into(), "10002".into())].into(),
                sensitive_values: vec!["cold".into(), "cold".into()],
                count: 2,
            },
        ];
        let result = check_t_closeness(&groups, 0.1);
        assert!(!result.satisfied);
    }

    #[test]
    fn test_reidentification_risk_low() {
        let records = vec![
            make_record(&[("zip", "10001"), ("age", "30")]),
            make_record(&[("zip", "10001"), ("age", "30")]),
            make_record(&[("zip", "10001"), ("age", "30")]),
            make_record(&[("zip", "10002"), ("age", "40")]),
            make_record(&[("zip", "10002"), ("age", "40")]),
            make_record(&[("zip", "10002"), ("age", "40")]),
        ];
        let risk = reidentification_risk(&records, &["zip".into(), "age".into()]);
        assert_eq!(risk.unique_records, 0);
        assert!(risk.score < 0.5);
    }

    #[test]
    fn test_reidentification_risk_high() {
        let records = vec![
            make_record(&[("zip", "10001"), ("age", "25")]),
            make_record(&[("zip", "10002"), ("age", "30")]),
            make_record(&[("zip", "10003"), ("age", "35")]),
        ];
        let risk = reidentification_risk(&records, &["zip".into(), "age".into()]);
        assert_eq!(risk.unique_records, 3);
        assert!(risk.score >= 0.5);
        assert!(!risk.recommendations.is_empty());
    }

    #[test]
    fn test_reidentification_risk_empty() {
        let risk = reidentification_risk(&[], &["zip".into()]);
        assert_eq!(risk.risk_level, RiskLevel::Negligible);
        assert_eq!(risk.total_records, 0);
    }

    #[test]
    fn test_generalization_hierarchy_age() {
        let h = GeneralizationHierarchy::age();
        assert_eq!(h.generalize("34", 0), "34");
        assert_eq!(h.generalize("34", 1), "30-34");
        assert_eq!(h.generalize("34", 2), "30-39");
        assert_eq!(h.generalize("34", 3), "*");
        assert_eq!(h.max_level(), 3);
    }

    #[test]
    fn test_generalization_hierarchy_zip() {
        let h = GeneralizationHierarchy::zip_code();
        assert_eq!(h.generalize("10001", 1), "100**");
        assert_eq!(h.generalize("10001", 2), "1****");
        assert_eq!(h.generalize("10001", 3), "*****");
    }

    #[test]
    fn test_generalization_hierarchy_date() {
        let h = GeneralizationHierarchy::date();
        assert_eq!(h.generalize("2024-03-15", 1), "2024-03");
        assert_eq!(h.generalize("2024-03-15", 2), "2024");
        assert_eq!(h.generalize("2024-03-15", 3), "*");
    }

    #[test]
    fn test_risk_level_display() {
        assert_eq!(RiskLevel::Negligible.to_string(), "Negligible");
        assert_eq!(RiskLevel::Critical.to_string(), "Critical");
    }
}
