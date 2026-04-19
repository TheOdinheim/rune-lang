// ═══════════════════════════════════════════════════════════════════════
// Threat Modeling — STRIDE + AI-specific threats
//
// Threat categories, threat actors, attack surfaces, identified threats,
// and a builder for constructing threat models. Adapted from STRIDE with
// AI-specific additions (prompt injection, data poisoning, etc.).
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use rune_permissions::Pillar;
use serde::{Deserialize, Serialize};

use crate::severity::SecuritySeverity;

// ── ThreatCategory ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatCategory {
    // STRIDE
    Spoofing,
    Tampering,
    Repudiation,
    InformationDisclosure,
    DenialOfService,
    ElevationOfPrivilege,
    // AI-specific
    PromptInjection,
    DataPoisoning,
    ModelExfiltration,
    AdversarialInput,
    GovernanceBypass,
    // Shared
    SupplyChainCompromise,
    InsiderThreat,
}

impl ThreatCategory {
    pub fn is_stride(&self) -> bool {
        matches!(
            self,
            Self::Spoofing
                | Self::Tampering
                | Self::Repudiation
                | Self::InformationDisclosure
                | Self::DenialOfService
                | Self::ElevationOfPrivilege
        )
    }

    pub fn is_ai_specific(&self) -> bool {
        matches!(
            self,
            Self::PromptInjection
                | Self::DataPoisoning
                | Self::ModelExfiltration
                | Self::AdversarialInput
                | Self::GovernanceBypass
        )
    }

    /// Which RUNE pillar(s) this threat category primarily targets.
    pub fn affected_pillar(&self) -> Vec<Pillar> {
        match self {
            Self::Spoofing => vec![Pillar::ZeroTrustThroughout],
            Self::Tampering => vec![Pillar::SecurityBakedIn],
            Self::Repudiation => vec![Pillar::SecurityBakedIn],
            Self::InformationDisclosure => vec![Pillar::SecurityBakedIn],
            Self::DenialOfService => vec![Pillar::NoSinglePointsOfFailure],
            Self::ElevationOfPrivilege => vec![Pillar::ZeroTrustThroughout],
            Self::PromptInjection => {
                vec![Pillar::SecurityBakedIn, Pillar::AssumedBreach]
            }
            Self::DataPoisoning => vec![Pillar::SecurityBakedIn],
            Self::ModelExfiltration => vec![Pillar::ZeroTrustThroughout],
            Self::AdversarialInput => vec![Pillar::SecurityBakedIn],
            Self::GovernanceBypass => vec![
                Pillar::SecurityBakedIn,
                Pillar::AssumedBreach,
                Pillar::NoSinglePointsOfFailure,
                Pillar::ZeroTrustThroughout,
            ],
            Self::SupplyChainCompromise => vec![Pillar::AssumedBreach],
            Self::InsiderThreat => {
                vec![Pillar::AssumedBreach, Pillar::ZeroTrustThroughout]
            }
        }
    }

    /// MITRE ATT&CK tactic ID where a direct mapping exists.
    pub fn mitre_attack_id(&self) -> Option<&'static str> {
        match self {
            Self::Spoofing => Some("TA0006"),             // Credential Access
            Self::Tampering => Some("TA0040"),            // Impact
            Self::InformationDisclosure => Some("TA0009"), // Collection
            Self::DenialOfService => Some("TA0040"),      // Impact
            Self::ElevationOfPrivilege => Some("TA0004"), // Privilege Escalation
            Self::SupplyChainCompromise => Some("TA0001"), // Initial Access
            Self::InsiderThreat => Some("TA0003"),        // Persistence
            _ => None,
        }
    }
}

impl fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── ThreatActorType ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatActorType {
    NationState,
    OrganizedCrime,
    Hacktivist,
    InsiderMalicious,
    InsiderNegligent,
    ScriptKiddie,
    AdvancedPersistentThreat,
    CompetitorEspionage,
    AiAgent,
}

impl fmt::Display for ThreatActorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── ActorSophistication ───────────────────────────────────────────────

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum ActorSophistication {
    Novice = 0,
    Intermediate = 1,
    Advanced = 2,
    Expert = 3,
    NationStateLevel = 4,
}

impl fmt::Display for ActorSophistication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── ActorMotivation ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActorMotivation {
    Financial,
    Espionage,
    Disruption,
    Ideological,
    Revenge,
    Curiosity,
    Competitive,
}

impl fmt::Display for ActorMotivation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── ThreatActor ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ThreatActor {
    pub id: String,
    pub name: String,
    pub actor_type: ThreatActorType,
    pub sophistication: ActorSophistication,
    pub motivation: Vec<ActorMotivation>,
    pub capabilities: Vec<String>,
    pub known_ttps: Vec<String>,
    pub active: bool,
}

// ── SurfaceType ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SurfaceType {
    NetworkEndpoint,
    UserInterface,
    DataStore,
    ModelEndpoint,
    SupplyChain,
    InternalApi,
    PhysicalAccess,
}

impl fmt::Display for SurfaceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── ExposureLevel ─────────────────────────────────────────────────────

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum ExposureLevel {
    Internal = 0,
    Partner = 1,
    Authenticated = 2,
    Public = 3,
}

impl fmt::Display for ExposureLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── AttackSurface ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AttackSurface {
    pub id: String,
    pub name: String,
    pub surface_type: SurfaceType,
    pub exposure: ExposureLevel,
    pub threats: Vec<ThreatCategory>,
    pub controls: Vec<String>,
    pub risk_score: f64,
}

// ── ThreatStatus ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatStatus {
    Identified,
    Analyzed,
    Mitigated,
    Accepted,
    Transferred,
    Monitoring,
}

impl fmt::Display for ThreatStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── IdentifiedThreat ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IdentifiedThreat {
    pub id: String,
    pub category: ThreatCategory,
    pub description: String,
    pub target_surface: String,
    pub actor_type: Option<ThreatActorType>,
    pub likelihood: SecuritySeverity,
    pub impact: SecuritySeverity,
    pub overall_risk: SecuritySeverity,
    pub mitigations: Vec<String>,
    pub status: ThreatStatus,
}

// ── ThreatModel ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ThreatModel {
    pub id: String,
    pub name: String,
    pub description: String,
    pub scope: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub author: String,
    pub actors: Vec<ThreatActor>,
    pub surfaces: Vec<AttackSurface>,
    pub threats: Vec<IdentifiedThreat>,
    pub assumptions: Vec<String>,
}

// ── ThreatModelBuilder ────────────────────────────────────────────────

pub struct ThreatModelBuilder {
    name: String,
    author: String,
    description: String,
    scope: String,
    actors: Vec<ThreatActor>,
    surfaces: Vec<AttackSurface>,
    threats: Vec<IdentifiedThreat>,
    assumptions: Vec<String>,
}

impl ThreatModelBuilder {
    pub fn new(name: &str, author: &str) -> Self {
        Self {
            name: name.into(),
            author: author.into(),
            description: String::new(),
            scope: String::new(),
            actors: Vec::new(),
            surfaces: Vec::new(),
            threats: Vec::new(),
            assumptions: Vec::new(),
        }
    }

    pub fn description(&mut self, desc: &str) -> &mut Self {
        self.description = desc.into();
        self
    }

    pub fn scope(&mut self, scope: &str) -> &mut Self {
        self.scope = scope.into();
        self
    }

    pub fn add_actor(&mut self, actor: ThreatActor) -> &mut Self {
        self.actors.push(actor);
        self
    }

    pub fn add_surface(&mut self, surface: AttackSurface) -> &mut Self {
        self.surfaces.push(surface);
        self
    }

    pub fn add_threat(&mut self, threat: IdentifiedThreat) -> &mut Self {
        self.threats.push(threat);
        self
    }

    pub fn add_assumption(&mut self, assumption: &str) -> &mut Self {
        self.assumptions.push(assumption.into());
        self
    }

    pub fn build(&self) -> ThreatModel {
        ThreatModel {
            id: format!("tm-{}", self.name.to_lowercase().replace(' ', "-")),
            name: self.name.clone(),
            description: self.description.clone(),
            scope: self.scope.clone(),
            created_at: 0,
            updated_at: 0,
            author: self.author.clone(),
            actors: self.actors.clone(),
            surfaces: self.surfaces.clone(),
            threats: self.threats.clone(),
            assumptions: self.assumptions.clone(),
        }
    }

    /// Highest risk among unmitigated threats.
    pub fn overall_risk(&self) -> SecuritySeverity {
        self.threats
            .iter()
            .filter(|t| !matches!(t.status, ThreatStatus::Mitigated))
            .map(|t| t.overall_risk)
            .max()
            .unwrap_or(SecuritySeverity::Info)
    }

    pub fn unmitigated_threats(&self) -> Vec<&IdentifiedThreat> {
        self.threats
            .iter()
            .filter(|t| !matches!(t.status, ThreatStatus::Mitigated))
            .collect()
    }

    pub fn threats_by_category(&self, category: &ThreatCategory) -> Vec<&IdentifiedThreat> {
        self.threats.iter().filter(|t| &t.category == category).collect()
    }

    pub fn threats_by_surface(&self, surface_id: &str) -> Vec<&IdentifiedThreat> {
        self.threats
            .iter()
            .filter(|t| t.target_surface == surface_id)
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Attack Tree Modeling and Attack Surface Mapping
// ═══════════════════════════════════════════════════════════════════════

/// Type of node in an attack tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttackNodeType {
    /// All children must succeed for this node to succeed.
    And,
    /// Any child succeeding means this node succeeds.
    Or,
    /// Terminal action the attacker takes.
    Leaf,
}

/// A node in an attack tree.
#[derive(Debug, Clone)]
pub struct AttackNode {
    pub id: String,
    pub description: String,
    pub node_type: AttackNodeType,
    pub children: Vec<AttackNode>,
    pub likelihood: f64,
    pub impact: f64,
    pub cost_to_attacker: f64,
    pub mitigations: Vec<String>,
}

impl AttackNode {
    pub fn leaf(id: &str, description: &str, likelihood: f64, impact: f64) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            node_type: AttackNodeType::Leaf,
            children: Vec::new(),
            likelihood,
            impact,
            cost_to_attacker: 1.0,
            mitigations: Vec::new(),
        }
    }

    pub fn risk_score(&self) -> f64 {
        match self.node_type {
            AttackNodeType::Leaf => self.likelihood * self.impact,
            AttackNodeType::Or => {
                let max_child = self
                    .children
                    .iter()
                    .map(|c| c.risk_score())
                    .fold(0.0_f64, f64::max);
                max_child * self.impact
            }
            AttackNodeType::And => {
                let product_likelihoods: f64 = self
                    .children
                    .iter()
                    .map(|c| c.likelihood)
                    .product();
                product_likelihoods * self.impact
            }
        }
    }
}

/// An attack tree rooted at a single goal.
#[derive(Debug, Clone)]
pub struct AttackTree {
    pub root: AttackNode,
    pub name: String,
    pub target: String,
    pub created_at: i64,
}

impl AttackTree {
    pub fn new(name: &str, target: &str, root: AttackNode) -> Self {
        Self {
            root,
            name: name.into(),
            target: target.into(),
            created_at: 0,
        }
    }

    pub fn all_attack_paths(&self) -> Vec<Vec<String>> {
        let mut paths = Vec::new();
        Self::collect_paths(&self.root, &mut Vec::new(), &mut paths);
        paths
    }

    fn collect_paths(node: &AttackNode, current: &mut Vec<String>, paths: &mut Vec<Vec<String>>) {
        current.push(node.id.clone());
        match node.node_type {
            AttackNodeType::Leaf => {
                paths.push(current.clone());
            }
            AttackNodeType::Or => {
                for child in &node.children {
                    Self::collect_paths(child, current, paths);
                }
            }
            AttackNodeType::And => {
                // For And, a single path includes all children
                let mut combined = current.clone();
                for child in &node.children {
                    let mut sub_paths = Vec::new();
                    Self::collect_paths(child, &mut Vec::new(), &mut sub_paths);
                    for sp in &sub_paths {
                        combined.extend(sp.iter().cloned());
                    }
                }
                paths.push(combined);
            }
        }
        current.pop();
    }

    pub fn highest_risk_path(&self) -> Option<(Vec<String>, f64)> {
        let paths = self.all_attack_paths();
        if paths.is_empty() {
            return None;
        }
        // Use root risk score as the overall risk, return path with most nodes
        // Actually, compute risk per path based on leaf scores
        let mut best: Option<(Vec<String>, f64)> = None;
        for path in paths {
            let risk = self.root.risk_score();
            match &best {
                None => best = Some((path, risk)),
                Some((_, br)) => {
                    if risk > *br {
                        best = Some((path, risk));
                    }
                }
            }
        }
        best
    }

    pub fn unmitigated_leaves(&self) -> Vec<&AttackNode> {
        let mut result = Vec::new();
        Self::collect_unmitigated(&self.root, &mut result);
        result
    }

    fn collect_unmitigated<'a>(node: &'a AttackNode, result: &mut Vec<&'a AttackNode>) {
        if node.node_type == AttackNodeType::Leaf {
            if node.mitigations.is_empty() {
                result.push(node);
            }
        } else {
            for child in &node.children {
                Self::collect_unmitigated(child, result);
            }
        }
    }

    pub fn total_leaf_count(&self) -> usize {
        Self::count_leaves(&self.root)
    }

    fn count_leaves(node: &AttackNode) -> usize {
        if node.node_type == AttackNodeType::Leaf {
            1
        } else {
            node.children.iter().map(|c| Self::count_leaves(c)).sum()
        }
    }
}

/// Exposure level for Layer 2 attack surface entry points.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum L2ExposureLevel {
    Isolated,
    Restricted,
    Internal,
    Public,
}

/// An entry point in the attack surface.
#[derive(Debug, Clone)]
pub struct EntryPoint {
    pub id: String,
    pub description: String,
    pub protocol: String,
    pub authentication_required: bool,
    pub exposure: L2ExposureLevel,
}

impl EntryPoint {
    pub fn risk_score(&self) -> f64 {
        let exposure_weight = match self.exposure {
            L2ExposureLevel::Isolated => 0.1,
            L2ExposureLevel::Restricted => 0.3,
            L2ExposureLevel::Internal => 0.5,
            L2ExposureLevel::Public => 1.0,
        };
        let auth_weight = if self.authentication_required { 0.5 } else { 1.0 };
        exposure_weight * auth_weight
    }
}

/// An attack surface composed of entry points.
#[derive(Debug, Clone)]
pub struct L2AttackSurface {
    pub name: String,
    pub entry_points: Vec<EntryPoint>,
}

impl L2AttackSurface {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            entry_points: Vec::new(),
        }
    }

    pub fn add_entry_point(&mut self, ep: EntryPoint) {
        self.entry_points.push(ep);
    }

    pub fn risk_score(&self) -> f64 {
        if self.entry_points.is_empty() {
            return 0.0;
        }
        self.entry_points.iter().map(|e| e.risk_score()).fold(0.0_f64, f64::max)
    }

    pub fn unauthenticated_public_count(&self) -> usize {
        self.entry_points
            .iter()
            .filter(|e| !e.authentication_required && e.exposure == L2ExposureLevel::Public)
            .count()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_threat(id: &str, category: ThreatCategory, risk: SecuritySeverity) -> IdentifiedThreat {
        IdentifiedThreat {
            id: id.into(),
            category,
            description: "test".into(),
            target_surface: "s1".into(),
            actor_type: None,
            likelihood: SecuritySeverity::Medium,
            impact: SecuritySeverity::Medium,
            overall_risk: risk,
            mitigations: vec![],
            status: ThreatStatus::Identified,
        }
    }

    #[test]
    fn test_is_stride() {
        assert!(ThreatCategory::Spoofing.is_stride());
        assert!(ThreatCategory::Tampering.is_stride());
        assert!(ThreatCategory::Repudiation.is_stride());
        assert!(ThreatCategory::InformationDisclosure.is_stride());
        assert!(ThreatCategory::DenialOfService.is_stride());
        assert!(ThreatCategory::ElevationOfPrivilege.is_stride());
        assert!(!ThreatCategory::PromptInjection.is_stride());
    }

    #[test]
    fn test_is_ai_specific() {
        assert!(ThreatCategory::PromptInjection.is_ai_specific());
        assert!(ThreatCategory::DataPoisoning.is_ai_specific());
        assert!(ThreatCategory::ModelExfiltration.is_ai_specific());
        assert!(ThreatCategory::AdversarialInput.is_ai_specific());
        assert!(ThreatCategory::GovernanceBypass.is_ai_specific());
        assert!(!ThreatCategory::Spoofing.is_ai_specific());
    }

    #[test]
    fn test_affected_pillar_spot_checks() {
        assert_eq!(
            ThreatCategory::Spoofing.affected_pillar(),
            vec![Pillar::ZeroTrustThroughout]
        );
        assert_eq!(
            ThreatCategory::DenialOfService.affected_pillar(),
            vec![Pillar::NoSinglePointsOfFailure]
        );
        assert_eq!(
            ThreatCategory::GovernanceBypass.affected_pillar().len(),
            4
        );
        assert_eq!(
            ThreatCategory::InsiderThreat.affected_pillar().len(),
            2
        );
    }

    #[test]
    fn test_mitre_mapping() {
        assert!(ThreatCategory::Spoofing.mitre_attack_id().is_some());
        assert!(ThreatCategory::PromptInjection.mitre_attack_id().is_none());
    }

    #[test]
    fn test_threat_actor_construction() {
        let actor = ThreatActor {
            id: "a1".into(),
            name: "APT28".into(),
            actor_type: ThreatActorType::NationState,
            sophistication: ActorSophistication::NationStateLevel,
            motivation: vec![ActorMotivation::Espionage],
            capabilities: vec!["zero-day exploits".into()],
            known_ttps: vec!["spear phishing".into()],
            active: true,
        };
        assert_eq!(actor.name, "APT28");
    }

    #[test]
    fn test_threat_actor_type_display() {
        assert_eq!(ThreatActorType::NationState.to_string(), "NationState");
        assert_eq!(ThreatActorType::AiAgent.to_string(), "AiAgent");
    }

    #[test]
    fn test_actor_sophistication_ordering() {
        assert!(ActorSophistication::Novice < ActorSophistication::Expert);
        assert!(ActorSophistication::Expert < ActorSophistication::NationStateLevel);
    }

    #[test]
    fn test_attack_surface_construction() {
        let s = AttackSurface {
            id: "s1".into(),
            name: "API".into(),
            surface_type: SurfaceType::NetworkEndpoint,
            exposure: ExposureLevel::Public,
            threats: vec![ThreatCategory::DenialOfService],
            controls: vec!["rate limiting".into()],
            risk_score: 7.5,
        };
        assert_eq!(s.exposure, ExposureLevel::Public);
    }

    #[test]
    fn test_exposure_level_ordering() {
        assert!(ExposureLevel::Internal < ExposureLevel::Partner);
        assert!(ExposureLevel::Partner < ExposureLevel::Authenticated);
        assert!(ExposureLevel::Authenticated < ExposureLevel::Public);
    }

    #[test]
    fn test_builder_constructs_model() {
        let mut b = ThreatModelBuilder::new("API Threat Model", "security-team");
        b.description("Public API threat model")
            .scope("REST API endpoints");
        let model = b.build();
        assert_eq!(model.name, "API Threat Model");
        assert_eq!(model.scope, "REST API endpoints");
    }

    #[test]
    fn test_builder_overall_risk() {
        let mut b = ThreatModelBuilder::new("Test", "author");
        b.add_threat(test_threat("t1", ThreatCategory::Spoofing, SecuritySeverity::Medium));
        b.add_threat(test_threat(
            "t2",
            ThreatCategory::DenialOfService,
            SecuritySeverity::Critical,
        ));
        b.add_threat(test_threat("t3", ThreatCategory::Tampering, SecuritySeverity::Low));
        assert_eq!(b.overall_risk(), SecuritySeverity::Critical);
    }

    #[test]
    fn test_builder_unmitigated_excludes_mitigated() {
        let mut b = ThreatModelBuilder::new("Test", "author");
        b.add_threat(test_threat(
            "t1",
            ThreatCategory::Spoofing,
            SecuritySeverity::Critical,
        ));
        let mut t2 = test_threat("t2", ThreatCategory::Tampering, SecuritySeverity::High);
        t2.status = ThreatStatus::Mitigated;
        b.add_threat(t2);
        assert_eq!(b.unmitigated_threats().len(), 1);
        assert_eq!(b.overall_risk(), SecuritySeverity::Critical);
    }

    #[test]
    fn test_threats_by_category() {
        let mut b = ThreatModelBuilder::new("Test", "author");
        b.add_threat(test_threat("t1", ThreatCategory::Spoofing, SecuritySeverity::Low));
        b.add_threat(test_threat("t2", ThreatCategory::Spoofing, SecuritySeverity::High));
        b.add_threat(test_threat(
            "t3",
            ThreatCategory::DenialOfService,
            SecuritySeverity::Medium,
        ));
        assert_eq!(b.threats_by_category(&ThreatCategory::Spoofing).len(), 2);
    }

    #[test]
    fn test_threats_by_surface() {
        let mut b = ThreatModelBuilder::new("Test", "author");
        let mut t1 = test_threat("t1", ThreatCategory::Spoofing, SecuritySeverity::Low);
        t1.target_surface = "api".into();
        let mut t2 = test_threat("t2", ThreatCategory::Tampering, SecuritySeverity::High);
        t2.target_surface = "db".into();
        b.add_threat(t1);
        b.add_threat(t2);
        assert_eq!(b.threats_by_surface("api").len(), 1);
    }

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_attack_node_leaf_risk_score() {
        let node = AttackNode::leaf("l1", "phishing", 0.8, 0.9);
        assert!((node.risk_score() - 0.72).abs() < 1e-9);
    }

    #[test]
    fn test_attack_node_or_risk_score() {
        let c1 = AttackNode::leaf("c1", "a", 0.5, 0.8);
        let c2 = AttackNode::leaf("c2", "b", 0.9, 0.6);
        let node = AttackNode {
            id: "or1".into(),
            description: "either".into(),
            node_type: AttackNodeType::Or,
            children: vec![c1, c2],
            likelihood: 1.0,
            impact: 1.0,
            cost_to_attacker: 1.0,
            mitigations: vec![],
        };
        // max child risk = max(0.5*0.8, 0.9*0.6) = max(0.4, 0.54) = 0.54
        // * impact(1.0) = 0.54
        assert!((node.risk_score() - 0.54).abs() < 1e-9);
    }

    #[test]
    fn test_attack_node_and_risk_score() {
        let c1 = AttackNode::leaf("c1", "a", 0.5, 0.8);
        let c2 = AttackNode::leaf("c2", "b", 0.6, 0.7);
        let node = AttackNode {
            id: "and1".into(),
            description: "both".into(),
            node_type: AttackNodeType::And,
            children: vec![c1, c2],
            likelihood: 1.0,
            impact: 0.9,
            cost_to_attacker: 1.0,
            mitigations: vec![],
        };
        // product likelihoods = 0.5 * 0.6 = 0.3, * impact(0.9) = 0.27
        assert!((node.risk_score() - 0.27).abs() < 1e-9);
    }

    #[test]
    fn test_attack_tree_all_paths() {
        let c1 = AttackNode::leaf("c1", "a", 0.5, 0.8);
        let c2 = AttackNode::leaf("c2", "b", 0.9, 0.6);
        let root = AttackNode {
            id: "root".into(),
            description: "goal".into(),
            node_type: AttackNodeType::Or,
            children: vec![c1, c2],
            likelihood: 1.0,
            impact: 1.0,
            cost_to_attacker: 1.0,
            mitigations: vec![],
        };
        let tree = AttackTree::new("test", "target", root);
        let paths = tree.all_attack_paths();
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn test_attack_tree_highest_risk_path() {
        let c1 = AttackNode::leaf("c1", "a", 0.5, 0.8);
        let root = AttackNode {
            id: "root".into(),
            description: "goal".into(),
            node_type: AttackNodeType::Or,
            children: vec![c1],
            likelihood: 1.0,
            impact: 1.0,
            cost_to_attacker: 1.0,
            mitigations: vec![],
        };
        let tree = AttackTree::new("test", "target", root);
        let (path, risk) = tree.highest_risk_path().unwrap();
        assert!(!path.is_empty());
        assert!(risk > 0.0);
    }

    #[test]
    fn test_attack_tree_unmitigated_leaves() {
        let mut c1 = AttackNode::leaf("c1", "a", 0.5, 0.8);
        c1.mitigations.push("firewall".into());
        let c2 = AttackNode::leaf("c2", "b", 0.9, 0.6);
        let root = AttackNode {
            id: "root".into(),
            description: "goal".into(),
            node_type: AttackNodeType::Or,
            children: vec![c1, c2],
            likelihood: 1.0,
            impact: 1.0,
            cost_to_attacker: 1.0,
            mitigations: vec![],
        };
        let tree = AttackTree::new("test", "target", root);
        let unmitigated = tree.unmitigated_leaves();
        assert_eq!(unmitigated.len(), 1);
        assert_eq!(unmitigated[0].id, "c2");
    }

    #[test]
    fn test_l2_attack_surface_risk_higher_for_public() {
        let mut surface = L2AttackSurface::new("api");
        surface.add_entry_point(EntryPoint {
            id: "ep1".into(),
            description: "public api".into(),
            protocol: "HTTP".into(),
            authentication_required: false,
            exposure: L2ExposureLevel::Public,
        });
        let public_risk = surface.risk_score();

        let mut internal_surface = L2AttackSurface::new("internal");
        internal_surface.add_entry_point(EntryPoint {
            id: "ep2".into(),
            description: "internal api".into(),
            protocol: "gRPC".into(),
            authentication_required: true,
            exposure: L2ExposureLevel::Internal,
        });
        let internal_risk = internal_surface.risk_score();
        assert!(public_risk > internal_risk);
    }

    #[test]
    fn test_l2_attack_surface_unauthenticated_public_count() {
        let mut surface = L2AttackSurface::new("api");
        surface.add_entry_point(EntryPoint {
            id: "ep1".into(),
            description: "public".into(),
            protocol: "HTTP".into(),
            authentication_required: false,
            exposure: L2ExposureLevel::Public,
        });
        surface.add_entry_point(EntryPoint {
            id: "ep2".into(),
            description: "authed public".into(),
            protocol: "HTTP".into(),
            authentication_required: true,
            exposure: L2ExposureLevel::Public,
        });
        surface.add_entry_point(EntryPoint {
            id: "ep3".into(),
            description: "internal".into(),
            protocol: "gRPC".into(),
            authentication_required: false,
            exposure: L2ExposureLevel::Internal,
        });
        assert_eq!(surface.unauthenticated_public_count(), 1);
    }
}
