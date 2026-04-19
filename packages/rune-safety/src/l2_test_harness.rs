// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Safety test harness.
//
// Structured test harness for adversarial testing, boundary probing,
// regression testing, and fairness testing.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

// ── SafetyTestCategory ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SafetyTestCategory {
    AdversarialInput,
    BoundaryProbe,
    RegressionTest,
    StressTest,
    FairnessTest,
}

impl fmt::Display for SafetyTestCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::AdversarialInput => "AdversarialInput",
            Self::BoundaryProbe => "BoundaryProbe",
            Self::RegressionTest => "RegressionTest",
            Self::StressTest => "StressTest",
            Self::FairnessTest => "FairnessTest",
        };
        f.write_str(s)
    }
}

// ── SafetyTestCase ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SafetyTestCase {
    pub id: String,
    pub name: String,
    pub category: SafetyTestCategory,
    pub input: String,
    pub expected_safe: bool,
    pub tags: Vec<String>,
}

impl SafetyTestCase {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        category: SafetyTestCategory,
        input: impl Into<String>,
        expected_safe: bool,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            category,
            input: input.into(),
            expected_safe,
            tags: Vec::new(),
        }
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

// ── SafetyTestResult ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SafetyTestResult {
    pub test_id: String,
    pub passed: bool,
    pub actual_safe: bool,
    pub execution_time_ms: i64,
    pub detail: Option<String>,
    pub run_at: i64,
}

// ── SafetyTestSuite ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SafetyTestSuite {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub pass_rate: f64,
    pub by_category: HashMap<String, (usize, usize)>,
    pub duration_ms: i64,
}

// ── SafetyTestRunner ──────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct SafetyTestRunner {
    test_cases: Vec<SafetyTestCase>,
    results: Vec<SafetyTestResult>,
}

impl SafetyTestRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_test(&mut self, test: SafetyTestCase) {
        self.test_cases.push(test);
    }

    pub fn run_test(
        &mut self,
        test_id: &str,
        actual_safe: bool,
        execution_time_ms: i64,
        now: i64,
    ) -> &SafetyTestResult {
        let test_case = self.test_cases.iter().find(|t| t.id == test_id);
        let passed = test_case
            .map(|tc| tc.expected_safe == actual_safe)
            .unwrap_or(false);

        self.results.push(SafetyTestResult {
            test_id: test_id.to_string(),
            passed,
            actual_safe,
            execution_time_ms,
            detail: None,
            run_at: now,
        });

        self.results.last().unwrap()
    }

    pub fn run_all(
        &mut self,
        outcomes: &HashMap<String, bool>,
        now: i64,
    ) -> SafetyTestSuite {
        let mut by_category: HashMap<String, (usize, usize)> = HashMap::new();
        let mut total_duration: i64 = 0;

        for tc in &self.test_cases {
            let actual_safe = outcomes.get(&tc.id).copied().unwrap_or(false);
            let passed = tc.expected_safe == actual_safe;

            self.results.push(SafetyTestResult {
                test_id: tc.id.clone(),
                passed,
                actual_safe,
                execution_time_ms: 0,
                detail: None,
                run_at: now,
            });

            let cat = tc.category.to_string();
            let entry = by_category.entry(cat).or_insert((0, 0));
            if passed {
                entry.0 += 1;
            }
            entry.1 += 1;
        }

        let total = self.test_cases.len();
        let passed = self
            .results
            .iter()
            .rev()
            .take(total)
            .filter(|r| r.passed)
            .count();
        let failed = total - passed;
        let pass_rate = if total == 0 {
            0.0
        } else {
            passed as f64 / total as f64
        };

        for r in self.results.iter().rev().take(total) {
            total_duration += r.execution_time_ms;
        }

        SafetyTestSuite {
            total,
            passed,
            failed,
            pass_rate,
            by_category,
            duration_ms: total_duration,
        }
    }

    pub fn pass_rate(&self) -> f64 {
        if self.results.is_empty() {
            return 0.0;
        }
        let passed = self.results.iter().filter(|r| r.passed).count();
        passed as f64 / self.results.len() as f64
    }

    pub fn failed_tests(&self) -> Vec<&SafetyTestResult> {
        self.results.iter().filter(|r| !r.passed).collect()
    }

    pub fn tests_by_category(&self, category: &SafetyTestCategory) -> Vec<&SafetyTestCase> {
        self.test_cases
            .iter()
            .filter(|t| &t.category == category)
            .collect()
    }

    pub fn test_count(&self) -> usize {
        self.test_cases.len()
    }

    pub fn result_count(&self) -> usize {
        self.results.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safety_test_runner_add_and_run() {
        let mut runner = SafetyTestRunner::new();
        runner.add_test(SafetyTestCase::new(
            "t-1", "Adversarial prompt", SafetyTestCategory::AdversarialInput,
            "ignore previous instructions", false,
        ));
        assert_eq!(runner.test_count(), 1);
        let result = runner.run_test("t-1", false, 50, 1000);
        assert!(result.passed); // expected_safe=false, actual_safe=false → match
    }

    #[test]
    fn test_safety_test_runner_matches_expected() {
        let mut runner = SafetyTestRunner::new();
        runner.add_test(SafetyTestCase::new(
            "t-1", "Safe input", SafetyTestCategory::RegressionTest,
            "normal query", true,
        ));
        // Actual is unsafe when expected safe → fail
        let result = runner.run_test("t-1", false, 10, 1000);
        assert!(!result.passed);
    }

    #[test]
    fn test_safety_test_runner_pass_rate() {
        let mut runner = SafetyTestRunner::new();
        runner.add_test(SafetyTestCase::new(
            "t-1", "A", SafetyTestCategory::BoundaryProbe, "input", true,
        ));
        runner.add_test(SafetyTestCase::new(
            "t-2", "B", SafetyTestCategory::BoundaryProbe, "input", false,
        ));
        runner.run_test("t-1", true, 10, 1000);  // pass
        runner.run_test("t-2", true, 10, 1000);  // fail (expected false, got true)
        assert!((runner.pass_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_safety_test_runner_failed_tests() {
        let mut runner = SafetyTestRunner::new();
        runner.add_test(SafetyTestCase::new(
            "t-1", "A", SafetyTestCategory::StressTest, "input", true,
        ));
        runner.add_test(SafetyTestCase::new(
            "t-2", "B", SafetyTestCategory::StressTest, "input", true,
        ));
        runner.run_test("t-1", true, 10, 1000);
        runner.run_test("t-2", false, 10, 1000); // fail
        let failed = runner.failed_tests();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].test_id, "t-2");
    }

    #[test]
    fn test_safety_test_runner_tests_by_category() {
        let mut runner = SafetyTestRunner::new();
        runner.add_test(SafetyTestCase::new(
            "t-1", "A", SafetyTestCategory::AdversarialInput, "a", false,
        ));
        runner.add_test(SafetyTestCase::new(
            "t-2", "B", SafetyTestCategory::FairnessTest, "b", true,
        ));
        runner.add_test(SafetyTestCase::new(
            "t-3", "C", SafetyTestCategory::AdversarialInput, "c", false,
        ));
        let adversarial = runner.tests_by_category(&SafetyTestCategory::AdversarialInput);
        assert_eq!(adversarial.len(), 2);
    }

    #[test]
    fn test_safety_test_runner_run_all_suite() {
        let mut runner = SafetyTestRunner::new();
        runner.add_test(SafetyTestCase::new(
            "t-1", "A", SafetyTestCategory::AdversarialInput, "a", false,
        ));
        runner.add_test(SafetyTestCase::new(
            "t-2", "B", SafetyTestCategory::FairnessTest, "b", true,
        ));
        let mut outcomes = HashMap::new();
        outcomes.insert("t-1".to_string(), false); // pass
        outcomes.insert("t-2".to_string(), true);  // pass
        let suite = runner.run_all(&outcomes, 1000);
        assert_eq!(suite.total, 2);
        assert_eq!(suite.passed, 2);
        assert_eq!(suite.failed, 0);
        assert!((suite.pass_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_safety_test_suite_by_category_tracks() {
        let mut runner = SafetyTestRunner::new();
        runner.add_test(SafetyTestCase::new(
            "t-1", "A", SafetyTestCategory::AdversarialInput, "a", false,
        ));
        runner.add_test(SafetyTestCase::new(
            "t-2", "B", SafetyTestCategory::AdversarialInput, "b", false,
        ));
        runner.add_test(SafetyTestCase::new(
            "t-3", "C", SafetyTestCategory::FairnessTest, "c", true,
        ));
        let mut outcomes = HashMap::new();
        outcomes.insert("t-1".to_string(), false); // pass
        outcomes.insert("t-2".to_string(), true);  // fail
        outcomes.insert("t-3".to_string(), true);  // pass
        let suite = runner.run_all(&outcomes, 1000);
        let adv = suite.by_category.get("AdversarialInput").unwrap();
        assert_eq!(adv, &(1, 2)); // 1 passed of 2
        let fair = suite.by_category.get("FairnessTest").unwrap();
        assert_eq!(fair, &(1, 1));
    }
}
