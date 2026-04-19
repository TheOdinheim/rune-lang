// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Multi-framework compliance mapping.
//
// Structured framework definitions with controls, severity levels,
// categories, and built-in skeletons for NIST AI RMF, EU AI Act,
// and SOC 2.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

// ── ControlSeverity ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ControlSeverity {
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl fmt::Display for ControlSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Informational => "Informational",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        };
        f.write_str(s)
    }
}

// ── FrameworkControl ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FrameworkControl {
    pub control_id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub severity: ControlSeverity,
    pub required: bool,
}

impl FrameworkControl {
    pub fn new(
        control_id: impl Into<String>,
        title: impl Into<String>,
        category: impl Into<String>,
        severity: ControlSeverity,
        required: bool,
    ) -> Self {
        Self {
            control_id: control_id.into(),
            title: title.into(),
            description: String::new(),
            category: category.into(),
            severity,
            required,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
}

// ── FrameworkDefinition ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FrameworkDefinition {
    pub id: String,
    pub name: String,
    pub version: String,
    pub jurisdiction: String,
    pub effective_date: Option<i64>,
    pub controls: Vec<FrameworkControl>,
    pub categories: Vec<String>,
}

impl FrameworkDefinition {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
        jurisdiction: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            version: version.into(),
            jurisdiction: jurisdiction.into(),
            effective_date: None,
            controls: Vec::new(),
            categories: Vec::new(),
        }
    }

    pub fn with_control(mut self, control: FrameworkControl) -> Self {
        if !self.categories.contains(&control.category) {
            self.categories.push(control.category.clone());
        }
        self.controls.push(control);
        self
    }
}

// ── FrameworkRegistry ──────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct L2FrameworkRegistry {
    frameworks: HashMap<String, FrameworkDefinition>,
}

impl L2FrameworkRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, framework: FrameworkDefinition) {
        self.frameworks.insert(framework.id.clone(), framework);
    }

    pub fn get(&self, framework_id: &str) -> Option<&FrameworkDefinition> {
        self.frameworks.get(framework_id)
    }

    pub fn list_frameworks(&self) -> Vec<&str> {
        self.frameworks.keys().map(|s| s.as_str()).collect()
    }

    pub fn controls_by_category(&self, framework_id: &str, category: &str) -> Vec<&FrameworkControl> {
        self.frameworks
            .get(framework_id)
            .map(|fw| {
                fw.controls
                    .iter()
                    .filter(|c| c.category == category)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn required_controls(&self, framework_id: &str) -> Vec<&FrameworkControl> {
        self.frameworks
            .get(framework_id)
            .map(|fw| fw.controls.iter().filter(|c| c.required).collect())
            .unwrap_or_default()
    }

    pub fn framework_count(&self) -> usize {
        self.frameworks.len()
    }
}

// ── Built-in skeletons ─────────────────────────────────────────────

pub fn nist_ai_rmf_skeleton() -> FrameworkDefinition {
    FrameworkDefinition::new("nist-ai-rmf", "NIST AI Risk Management Framework", "1.0", "US")
        .with_control(FrameworkControl::new("GOV-1", "AI governance structure", "Govern", ControlSeverity::High, true))
        .with_control(FrameworkControl::new("GOV-2", "AI risk management policies", "Govern", ControlSeverity::High, true))
        .with_control(FrameworkControl::new("MAP-1", "AI system context mapping", "Map", ControlSeverity::Medium, true))
        .with_control(FrameworkControl::new("MAP-2", "Stakeholder identification", "Map", ControlSeverity::Medium, false))
        .with_control(FrameworkControl::new("MEA-1", "Performance measurement", "Measure", ControlSeverity::High, true))
        .with_control(FrameworkControl::new("MEA-2", "Bias and fairness metrics", "Measure", ControlSeverity::Critical, true))
        .with_control(FrameworkControl::new("MAN-1", "Risk response actions", "Manage", ControlSeverity::High, true))
        .with_control(FrameworkControl::new("MAN-2", "Continuous monitoring", "Manage", ControlSeverity::Medium, true))
}

pub fn eu_ai_act_skeleton() -> FrameworkDefinition {
    FrameworkDefinition::new("eu-ai-act", "EU Artificial Intelligence Act", "2024", "EU")
        .with_control(FrameworkControl::new("ART-6", "Risk classification", "Risk Categories", ControlSeverity::Critical, true))
        .with_control(FrameworkControl::new("ART-9", "Risk management system", "Risk Categories", ControlSeverity::High, true))
        .with_control(FrameworkControl::new("ART-10", "Data governance", "Data Governance", ControlSeverity::High, true))
        .with_control(FrameworkControl::new("ART-13", "Transparency requirements", "Transparency", ControlSeverity::High, true))
        .with_control(FrameworkControl::new("ART-14", "Human oversight", "Human Oversight", ControlSeverity::Critical, true))
        .with_control(FrameworkControl::new("ART-15", "Accuracy and robustness", "Accuracy", ControlSeverity::High, true))
}

pub fn soc2_skeleton() -> FrameworkDefinition {
    FrameworkDefinition::new("soc2", "SOC 2 Type II", "2017", "US")
        .with_control(FrameworkControl::new("CC-1", "Logical and physical access controls", "Security", ControlSeverity::High, true))
        .with_control(FrameworkControl::new("CC-2", "System monitoring", "Security", ControlSeverity::High, true))
        .with_control(FrameworkControl::new("A-1", "System availability monitoring", "Availability", ControlSeverity::Medium, true))
        .with_control(FrameworkControl::new("PI-1", "Processing completeness and accuracy", "Processing Integrity", ControlSeverity::Medium, true))
        .with_control(FrameworkControl::new("C-1", "Confidentiality commitments", "Confidentiality", ControlSeverity::High, true))
        .with_control(FrameworkControl::new("P-1", "Privacy notice and consent", "Privacy", ControlSeverity::High, true))
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_framework_registry_register_and_get() {
        let mut reg = L2FrameworkRegistry::new();
        reg.register(nist_ai_rmf_skeleton());
        assert!(reg.get("nist-ai-rmf").is_some());
        assert!(reg.get("nonexistent").is_none());
    }

    #[test]
    fn test_framework_registry_list_frameworks_returns_all() {
        let mut reg = L2FrameworkRegistry::new();
        reg.register(nist_ai_rmf_skeleton());
        reg.register(eu_ai_act_skeleton());
        reg.register(soc2_skeleton());
        assert_eq!(reg.framework_count(), 3);
        let list = reg.list_frameworks();
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn test_framework_registry_controls_by_category_filters_correctly() {
        let mut reg = L2FrameworkRegistry::new();
        reg.register(nist_ai_rmf_skeleton());
        let govern = reg.controls_by_category("nist-ai-rmf", "Govern");
        assert_eq!(govern.len(), 2);
        let map = reg.controls_by_category("nist-ai-rmf", "Map");
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_framework_registry_required_controls_returns_only_required() {
        let mut reg = L2FrameworkRegistry::new();
        reg.register(nist_ai_rmf_skeleton());
        let required = reg.required_controls("nist-ai-rmf");
        // MAP-2 is not required
        assert_eq!(required.len(), 7);
        assert!(required.iter().all(|c| c.required));
    }

    #[test]
    fn test_nist_ai_rmf_skeleton_has_4_categories() {
        let fw = nist_ai_rmf_skeleton();
        assert_eq!(fw.categories.len(), 4);
        assert!(fw.categories.contains(&"Govern".to_string()));
        assert!(fw.categories.contains(&"Map".to_string()));
        assert!(fw.categories.contains(&"Measure".to_string()));
        assert!(fw.categories.contains(&"Manage".to_string()));
    }

    #[test]
    fn test_eu_ai_act_skeleton_has_risk_categories_and_key_articles() {
        let fw = eu_ai_act_skeleton();
        assert!(fw.controls.iter().any(|c| c.control_id == "ART-6"));
        assert!(fw.controls.iter().any(|c| c.control_id == "ART-13"));
        assert!(fw.controls.iter().any(|c| c.control_id == "ART-14"));
        assert!(fw.categories.contains(&"Risk Categories".to_string()));
        assert!(fw.categories.contains(&"Transparency".to_string()));
    }

    #[test]
    fn test_soc2_skeleton_has_5_trust_service_criteria() {
        let fw = soc2_skeleton();
        assert_eq!(fw.categories.len(), 5);
        assert!(fw.categories.contains(&"Security".to_string()));
        assert!(fw.categories.contains(&"Availability".to_string()));
        assert!(fw.categories.contains(&"Processing Integrity".to_string()));
        assert!(fw.categories.contains(&"Confidentiality".to_string()));
        assert!(fw.categories.contains(&"Privacy".to_string()));
    }
}
