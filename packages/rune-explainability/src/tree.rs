// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Structured decision explanation trees.
//
// ExplanationNode / ExplanationTree represent hierarchical decision logic.
// ExplanationTreeBuilder provides a fluent API for tree construction.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

// ── ExplanationNodeType ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplanationNodeType {
    Root,
    Factor,
    Condition,
    Threshold,
    Override,
    Default,
}

impl fmt::Display for ExplanationNodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root => f.write_str("root"),
            Self::Factor => f.write_str("factor"),
            Self::Condition => f.write_str("condition"),
            Self::Threshold => f.write_str("threshold"),
            Self::Override => f.write_str("override"),
            Self::Default => f.write_str("default"),
        }
    }
}

// ── ExplanationNode ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ExplanationNode {
    pub id: String,
    pub description: String,
    pub node_type: ExplanationNodeType,
    pub children: Vec<ExplanationNode>,
    pub weight: f64,
    pub evidence: Vec<String>,
    pub outcome: Option<String>,
}

impl ExplanationNode {
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        node_type: ExplanationNodeType,
        weight: f64,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            node_type,
            children: Vec::new(),
            weight,
            evidence: Vec::new(),
            outcome: None,
        }
    }

    pub fn with_outcome(mut self, outcome: impl Into<String>) -> Self {
        self.outcome = Some(outcome.into());
        self
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence.push(evidence.into());
        self
    }

    pub fn with_child(mut self, child: ExplanationNode) -> Self {
        self.children.push(child);
        self
    }

    fn depth(&self) -> usize {
        if self.children.is_empty() {
            1
        } else {
            1 + self.children.iter().map(|c| c.depth()).max().unwrap_or(0)
        }
    }

    fn count_type(&self, node_type: &ExplanationNodeType) -> usize {
        let mut count = if self.node_type == *node_type { 1 } else { 0 };
        for child in &self.children {
            count += child.count_type(node_type);
        }
        count
    }

    fn collect_evidence<'a>(&'a self, out: &mut Vec<&'a str>) {
        for e in &self.evidence {
            out.push(e.as_str());
        }
        for child in &self.children {
            child.collect_evidence(out);
        }
    }

    fn critical_path<'a>(&'a self, path: &mut Vec<&'a ExplanationNode>) {
        path.push(self);
        if self.children.is_empty() {
            return;
        }
        let best = self
            .children
            .iter()
            .max_by(|a, b| a.weight.partial_cmp(&b.weight).unwrap_or(std::cmp::Ordering::Equal));
        if let Some(best) = best {
            best.critical_path(path);
        }
    }
}

// ── ExplanationTree ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ExplanationTree {
    pub root: ExplanationNode,
    pub decision_id: String,
    pub created_at: i64,
    pub model_id: Option<String>,
    pub policy_id: Option<String>,
}

impl ExplanationTree {
    pub fn new(decision_id: impl Into<String>, root: ExplanationNode, now: i64) -> Self {
        Self {
            root,
            decision_id: decision_id.into(),
            created_at: now,
            model_id: None,
            policy_id: None,
        }
    }

    pub fn with_model_id(mut self, model_id: impl Into<String>) -> Self {
        self.model_id = Some(model_id.into());
        self
    }

    pub fn with_policy_id(mut self, policy_id: impl Into<String>) -> Self {
        self.policy_id = Some(policy_id.into());
        self
    }

    pub fn depth(&self) -> usize {
        self.root.depth()
    }

    pub fn factor_count(&self) -> usize {
        self.root.count_type(&ExplanationNodeType::Factor)
    }

    pub fn critical_path(&self) -> Vec<&ExplanationNode> {
        let mut path = Vec::new();
        self.root.critical_path(&mut path);
        path
    }

    pub fn all_evidence(&self) -> Vec<&str> {
        let mut out = Vec::new();
        self.root.collect_evidence(&mut out);
        out
    }

    pub fn summary(&self) -> String {
        let outcome_str = self
            .root
            .outcome
            .as_deref()
            .unwrap_or("unknown");
        format!(
            "Decision {}: {} based on {} factors",
            self.decision_id,
            outcome_str,
            self.factor_count()
        )
    }
}

// ── ExplanationTreeBuilder ───────────────────────────────────────────

pub struct ExplanationTreeBuilder {
    decision_id: String,
    root: Option<ExplanationNode>,
    children: Vec<ExplanationNode>,
}

impl ExplanationTreeBuilder {
    pub fn new(decision_id: impl Into<String>) -> Self {
        Self {
            decision_id: decision_id.into(),
            root: None,
            children: Vec::new(),
        }
    }

    pub fn root(mut self, description: &str, outcome: &str) -> Self {
        self.root = Some(
            ExplanationNode::new("root", description, ExplanationNodeType::Root, 1.0)
                .with_outcome(outcome),
        );
        self
    }

    pub fn add_factor(mut self, id: &str, description: &str, weight: f64) -> Self {
        self.children.push(ExplanationNode::new(
            id,
            description,
            ExplanationNodeType::Factor,
            weight,
        ));
        self
    }

    pub fn add_condition(mut self, id: &str, description: &str, met: bool) -> Self {
        let outcome_str = if met { "condition met" } else { "condition not met" };
        self.children.push(
            ExplanationNode::new(
                id,
                description,
                ExplanationNodeType::Condition,
                if met { 1.0 } else { 0.0 },
            )
            .with_outcome(outcome_str),
        );
        self
    }

    pub fn add_threshold(
        mut self,
        id: &str,
        description: &str,
        value: f64,
        threshold: f64,
    ) -> Self {
        let exceeded = value >= threshold;
        let outcome_str = format!(
            "value {:.2} {} threshold {:.2}",
            value,
            if exceeded { ">=" } else { "<" },
            threshold
        );
        self.children.push(
            ExplanationNode::new(
                id,
                description,
                ExplanationNodeType::Threshold,
                if exceeded { 1.0 } else { 0.0 },
            )
            .with_outcome(outcome_str),
        );
        self
    }

    pub fn add_evidence(mut self, node_id: &str, evidence: &str) -> Self {
        // Try to find the node in children or root
        for child in &mut self.children {
            if child.id == node_id {
                child.evidence.push(evidence.into());
                return self;
            }
        }
        if let Some(root) = &mut self.root {
            if root.id == node_id {
                root.evidence.push(evidence.into());
            }
        }
        self
    }

    pub fn build(self, now: i64) -> ExplanationTree {
        let mut root = self.root.unwrap_or_else(|| {
            ExplanationNode::new("root", "Decision", ExplanationNodeType::Root, 1.0)
        });
        root.children = self.children;
        ExplanationTree::new(self.decision_id, root, now)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tree() -> ExplanationTree {
        let root = ExplanationNode::new("root", "Access decision", ExplanationNodeType::Root, 1.0)
            .with_outcome("denied")
            .with_evidence("Policy evaluated at 2026-04-19")
            .with_child(
                ExplanationNode::new(
                    "policy",
                    "Security policy check",
                    ExplanationNodeType::Factor,
                    0.7,
                )
                .with_evidence("Rule #42 matched"),
            )
            .with_child(
                ExplanationNode::new(
                    "trust",
                    "Trust score evaluation",
                    ExplanationNodeType::Factor,
                    0.3,
                )
                .with_evidence("Score: 0.85"),
            );
        ExplanationTree::new("d1", root, 1000)
    }

    #[test]
    fn test_explanation_node_construction() {
        for nt in [
            ExplanationNodeType::Root,
            ExplanationNodeType::Factor,
            ExplanationNodeType::Condition,
            ExplanationNodeType::Threshold,
            ExplanationNodeType::Override,
            ExplanationNodeType::Default,
        ] {
            let node = ExplanationNode::new("n", "desc", nt.clone(), 0.5);
            assert_eq!(node.node_type, nt);
            assert!(!node.node_type.to_string().is_empty());
        }
    }

    #[test]
    fn test_tree_depth() {
        let tree = sample_tree();
        assert_eq!(tree.depth(), 2); // root -> child
    }

    #[test]
    fn test_tree_factor_count() {
        let tree = sample_tree();
        assert_eq!(tree.factor_count(), 2);
    }

    #[test]
    fn test_tree_critical_path_follows_highest_weight() {
        let tree = sample_tree();
        let path = tree.critical_path();
        assert_eq!(path.len(), 2);
        assert_eq!(path[0].id, "root");
        assert_eq!(path[1].id, "policy"); // weight 0.7 > 0.3
    }

    #[test]
    fn test_tree_all_evidence() {
        let tree = sample_tree();
        let evidence = tree.all_evidence();
        assert_eq!(evidence.len(), 3);
        assert!(evidence.contains(&"Policy evaluated at 2026-04-19"));
        assert!(evidence.contains(&"Rule #42 matched"));
        assert!(evidence.contains(&"Score: 0.85"));
    }

    #[test]
    fn test_tree_summary() {
        let tree = sample_tree();
        let summary = tree.summary();
        assert!(summary.contains("d1"));
        assert!(summary.contains("denied"));
        assert!(summary.contains("2 factors"));
    }

    #[test]
    fn test_builder_fluent_api() {
        let tree = ExplanationTreeBuilder::new("d1")
            .root("Access decision", "approved")
            .add_factor("policy", "Policy check", 0.6)
            .add_factor("trust", "Trust score", 0.4)
            .build(1000);
        assert_eq!(tree.decision_id, "d1");
        assert_eq!(tree.factor_count(), 2);
        assert_eq!(tree.root.outcome.as_deref(), Some("approved"));
    }

    #[test]
    fn test_builder_add_evidence() {
        let tree = ExplanationTreeBuilder::new("d1")
            .root("Decision", "ok")
            .add_factor("f1", "Factor 1", 0.5)
            .add_evidence("f1", "Evidence for factor 1")
            .build(1000);
        let f1 = tree.root.children.iter().find(|c| c.id == "f1").unwrap();
        assert_eq!(f1.evidence.len(), 1);
        assert_eq!(f1.evidence[0], "Evidence for factor 1");
    }

    #[test]
    fn test_builder_with_conditions_and_thresholds() {
        let tree = ExplanationTreeBuilder::new("d1")
            .root("Decision", "approved")
            .add_condition("cond1", "Is admin?", true)
            .add_threshold("thresh1", "Risk score", 0.3, 0.5)
            .build(1000);
        assert_eq!(tree.root.children.len(), 2);
        let cond = &tree.root.children[0];
        assert_eq!(cond.node_type, ExplanationNodeType::Condition);
        assert_eq!(cond.outcome.as_deref(), Some("condition met"));
        let thresh = &tree.root.children[1];
        assert_eq!(thresh.node_type, ExplanationNodeType::Threshold);
        assert!(thresh.outcome.as_deref().unwrap().contains("<"));
    }
}
