// ═══════════════════════════════════════════════════════════════════════
// Baseline Store — Trait for baseline lifecycle management.
//
// Layer 3 separates baseline storage from DetectionBackend because
// baselines have a distinct lifecycle: they are trained, retrained,
// rolled back, and introspected. DetectionBackend has basic
// store/retrieve methods; BaselineStore adds the specialized
// lifecycle operations.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::error::DetectionError;

// ── Baseline ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Baseline {
    pub baseline_id: String,
    pub name: String,
    pub mean: String,
    pub std_dev: String,
    pub percentiles: HashMap<String, String>,
    pub sample_count: u64,
    pub trained_at: i64,
    pub trained_on: String,
}

impl Baseline {
    pub fn new(baseline_id: &str, name: &str, mean: &str, std_dev: &str) -> Self {
        Self {
            baseline_id: baseline_id.to_string(),
            name: name.to_string(),
            mean: mean.to_string(),
            std_dev: std_dev.to_string(),
            percentiles: HashMap::new(),
            sample_count: 0,
            trained_at: 0,
            trained_on: String::new(),
        }
    }

    pub fn with_sample_count(mut self, count: u64) -> Self {
        self.sample_count = count;
        self
    }

    pub fn with_trained_at(mut self, ts: i64) -> Self {
        self.trained_at = ts;
        self
    }

    pub fn with_trained_on(mut self, dataset: &str) -> Self {
        self.trained_on = dataset.to_string();
        self
    }

    pub fn with_percentile(mut self, key: &str, value: &str) -> Self {
        self.percentiles.insert(key.to_string(), value.to_string());
        self
    }
}

// ── BaselineMetadata ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineMetadata {
    pub baseline_id: String,
    pub name: String,
    pub sample_count: u64,
    pub trained_at: i64,
    pub trained_on: String,
}

// ── BaselineStore trait ────────────────────────────────────────

pub trait BaselineStore {
    fn store_baseline(&mut self, baseline: &Baseline) -> Result<(), DetectionError>;
    fn retrieve_baseline(&self, id: &str) -> Option<&Baseline>;
    fn update_baseline(&mut self, baseline: &Baseline) -> Result<(), DetectionError>;
    fn delete_baseline(&mut self, id: &str) -> Result<bool, DetectionError>;
    fn list_baselines(&self) -> Vec<&str>;
    fn baseline_count(&self) -> usize;
    fn baseline_metadata(&self, id: &str) -> Option<BaselineMetadata>;
}

// ── InMemoryBaselineStore ──────────────────────────────────────

pub struct InMemoryBaselineStore {
    baselines: HashMap<String, Baseline>,
}

impl InMemoryBaselineStore {
    pub fn new() -> Self {
        Self {
            baselines: HashMap::new(),
        }
    }
}

impl Default for InMemoryBaselineStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BaselineStore for InMemoryBaselineStore {
    fn store_baseline(&mut self, baseline: &Baseline) -> Result<(), DetectionError> {
        if self.baselines.contains_key(&baseline.baseline_id) {
            return Err(DetectionError::InvalidOperation(format!(
                "baseline already exists: {}",
                baseline.baseline_id
            )));
        }
        self.baselines.insert(baseline.baseline_id.clone(), baseline.clone());
        Ok(())
    }

    fn retrieve_baseline(&self, id: &str) -> Option<&Baseline> {
        self.baselines.get(id)
    }

    fn update_baseline(&mut self, baseline: &Baseline) -> Result<(), DetectionError> {
        if !self.baselines.contains_key(&baseline.baseline_id) {
            return Err(DetectionError::InvalidOperation(format!(
                "baseline not found: {}",
                baseline.baseline_id
            )));
        }
        self.baselines.insert(baseline.baseline_id.clone(), baseline.clone());
        Ok(())
    }

    fn delete_baseline(&mut self, id: &str) -> Result<bool, DetectionError> {
        Ok(self.baselines.remove(id).is_some())
    }

    fn list_baselines(&self) -> Vec<&str> {
        self.baselines.keys().map(|k| k.as_str()).collect()
    }

    fn baseline_count(&self) -> usize {
        self.baselines.len()
    }

    fn baseline_metadata(&self, id: &str) -> Option<BaselineMetadata> {
        self.baselines.get(id).map(|b| BaselineMetadata {
            baseline_id: b.baseline_id.clone(),
            name: b.name.clone(),
            sample_count: b.sample_count,
            trained_at: b.trained_at,
            trained_on: b.trained_on.clone(),
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_baseline(id: &str) -> Baseline {
        Baseline::new(id, &format!("baseline-{id}"), "10.5", "2.1")
            .with_sample_count(100)
            .with_trained_at(1000)
            .with_trained_on("dataset-a")
            .with_percentile("p50", "9.8")
            .with_percentile("p99", "15.2")
    }

    #[test]
    fn test_store_and_retrieve() {
        let mut store = InMemoryBaselineStore::new();
        store.store_baseline(&make_baseline("b1")).unwrap();
        let b = store.retrieve_baseline("b1");
        assert!(b.is_some());
        assert_eq!(b.unwrap().mean, "10.5");
    }

    #[test]
    fn test_duplicate_store_rejected() {
        let mut store = InMemoryBaselineStore::new();
        store.store_baseline(&make_baseline("b1")).unwrap();
        assert!(store.store_baseline(&make_baseline("b1")).is_err());
    }

    #[test]
    fn test_update_baseline() {
        let mut store = InMemoryBaselineStore::new();
        store.store_baseline(&make_baseline("b1")).unwrap();
        let updated = Baseline::new("b1", "baseline-b1", "12.0", "3.0")
            .with_sample_count(200)
            .with_trained_at(2000);
        store.update_baseline(&updated).unwrap();
        let b = store.retrieve_baseline("b1").unwrap();
        assert_eq!(b.mean, "12.0");
        assert_eq!(b.sample_count, 200);
    }

    #[test]
    fn test_update_nonexistent_rejected() {
        let mut store = InMemoryBaselineStore::new();
        assert!(store.update_baseline(&make_baseline("b1")).is_err());
    }

    #[test]
    fn test_delete_baseline() {
        let mut store = InMemoryBaselineStore::new();
        store.store_baseline(&make_baseline("b1")).unwrap();
        assert!(store.delete_baseline("b1").unwrap());
        assert!(!store.delete_baseline("b1").unwrap());
    }

    #[test]
    fn test_list_and_count() {
        let mut store = InMemoryBaselineStore::new();
        store.store_baseline(&make_baseline("b1")).unwrap();
        store.store_baseline(&make_baseline("b2")).unwrap();
        assert_eq!(store.baseline_count(), 2);
        assert_eq!(store.list_baselines().len(), 2);
    }

    #[test]
    fn test_baseline_metadata() {
        let mut store = InMemoryBaselineStore::new();
        store.store_baseline(&make_baseline("b1")).unwrap();
        let meta = store.baseline_metadata("b1").unwrap();
        assert_eq!(meta.baseline_id, "b1");
        assert_eq!(meta.sample_count, 100);
        assert_eq!(meta.trained_at, 1000);
        assert_eq!(meta.trained_on, "dataset-a");
    }

    #[test]
    fn test_baseline_metadata_missing() {
        let store = InMemoryBaselineStore::new();
        assert!(store.baseline_metadata("nope").is_none());
    }

    #[test]
    fn test_baseline_percentiles() {
        let b = make_baseline("b1");
        assert_eq!(b.percentiles.get("p50").unwrap(), "9.8");
        assert_eq!(b.percentiles.get("p99").unwrap(), "15.2");
    }

    #[test]
    fn test_baseline_eq() {
        let b1 = make_baseline("b1");
        let b2 = make_baseline("b1");
        assert_eq!(b1, b2);
    }
}
