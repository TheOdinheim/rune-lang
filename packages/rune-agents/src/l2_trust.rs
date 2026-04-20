// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Agent trust scoring.
//
// Dynamic trust scoring that evolves based on agent behavior, with
// decay over time and multi-dimensional scoring.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

// ── AgentTrustProfile ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AgentTrustProfile {
    pub agent_id: String,
    pub trust_score: f64,
    pub reliability_score: f64,
    pub safety_score: f64,
    pub cooperation_score: f64,
    pub total_interactions: u64,
    pub successful_interactions: u64,
    pub violations: u64,
    pub last_updated_at: i64,
}

// ── AgentTrustEngine ──────────────────────────────────────────────

#[derive(Debug)]
pub struct AgentTrustEngine {
    profiles: HashMap<String, AgentTrustProfile>,
    decay_rate: f64,
    recovery_rate: f64,
}

impl AgentTrustEngine {
    pub fn new(decay_rate: f64, recovery_rate: f64) -> Self {
        Self {
            profiles: HashMap::new(),
            decay_rate,
            recovery_rate,
        }
    }

    pub fn initialize_agent(&mut self, agent_id: &str, initial_trust: f64, now: i64) {
        self.profiles.insert(
            agent_id.to_string(),
            AgentTrustProfile {
                agent_id: agent_id.to_string(),
                trust_score: initial_trust,
                reliability_score: initial_trust,
                safety_score: 1.0,
                cooperation_score: initial_trust,
                total_interactions: 0,
                successful_interactions: 0,
                violations: 0,
                last_updated_at: now,
            },
        );
        self.recalculate_trust(agent_id);
    }

    pub fn record_success(&mut self, agent_id: &str, now: i64) {
        if let Some(profile) = self.profiles.get_mut(agent_id) {
            profile.total_interactions += 1;
            profile.successful_interactions += 1;
            profile.reliability_score = f64::min(
                1.0,
                profile.reliability_score + self.recovery_rate,
            );
            self.recalculate_trust(agent_id);
            if let Some(p) = self.profiles.get_mut(agent_id) {
                p.last_updated_at = now;
            }
        }
    }

    pub fn record_failure(&mut self, agent_id: &str, now: i64) {
        if let Some(profile) = self.profiles.get_mut(agent_id) {
            profile.total_interactions += 1;
            profile.reliability_score = f64::max(
                0.0,
                profile.reliability_score - self.recovery_rate * 2.0,
            );
            self.recalculate_trust(agent_id);
            if let Some(p) = self.profiles.get_mut(agent_id) {
                p.last_updated_at = now;
            }
        }
    }

    pub fn record_violation(&mut self, agent_id: &str, now: i64) {
        if let Some(profile) = self.profiles.get_mut(agent_id) {
            profile.violations += 1;
            profile.safety_score = f64::max(
                0.0,
                profile.safety_score - 0.1,
            );
            self.recalculate_trust(agent_id);
            if let Some(p) = self.profiles.get_mut(agent_id) {
                p.last_updated_at = now;
            }
        }
    }

    pub fn record_cooperation(&mut self, agent_id: &str, cooperated: bool, now: i64) {
        if let Some(profile) = self.profiles.get_mut(agent_id) {
            if cooperated {
                profile.cooperation_score = f64::min(
                    1.0,
                    profile.cooperation_score + self.recovery_rate,
                );
            } else {
                profile.cooperation_score = f64::max(
                    0.0,
                    profile.cooperation_score - self.recovery_rate * 2.0,
                );
            }
            self.recalculate_trust(agent_id);
            if let Some(p) = self.profiles.get_mut(agent_id) {
                p.last_updated_at = now;
            }
        }
    }

    fn recalculate_trust(&mut self, agent_id: &str) {
        if let Some(profile) = self.profiles.get_mut(agent_id) {
            // Weighted average: reliability 0.4, safety 0.35, cooperation 0.25
            profile.trust_score = profile.reliability_score * 0.4
                + profile.safety_score * 0.35
                + profile.cooperation_score * 0.25;
        }
    }

    pub fn trust_score(&self, agent_id: &str) -> Option<f64> {
        self.profiles.get(agent_id).map(|p| p.trust_score)
    }

    pub fn get_profile(&self, agent_id: &str) -> Option<&AgentTrustProfile> {
        self.profiles.get(agent_id)
    }

    pub fn apply_decay(&mut self, now: i64) {
        for profile in self.profiles.values_mut() {
            let elapsed_hours =
                (now - profile.last_updated_at) as f64 / 3_600_000.0;
            if elapsed_hours > 0.0 {
                let decay_factor = (-self.decay_rate * elapsed_hours).exp();
                profile.trust_score *= decay_factor;
                profile.reliability_score *= decay_factor;
                profile.cooperation_score *= decay_factor;
                profile.last_updated_at = now;
            }
        }
    }

    pub fn agents_above_threshold(&self, threshold: f64) -> Vec<&str> {
        self.profiles
            .iter()
            .filter(|(_, p)| p.trust_score >= threshold)
            .map(|(id, _)| id.as_str())
            .collect()
    }

    pub fn agents_below_threshold(&self, threshold: f64) -> Vec<&str> {
        self.profiles
            .iter()
            .filter(|(_, p)| p.trust_score < threshold)
            .map(|(id, _)| id.as_str())
            .collect()
    }

    pub fn least_trusted(&self, n: usize) -> Vec<(&str, f64)> {
        let mut pairs: Vec<(&str, f64)> = self
            .profiles
            .iter()
            .map(|(id, p)| (id.as_str(), p.trust_score))
            .collect();
        pairs.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        pairs.truncate(n);
        pairs
    }

    pub fn most_trusted(&self, n: usize) -> Vec<(&str, f64)> {
        let mut pairs: Vec<(&str, f64)> = self
            .profiles
            .iter()
            .map(|(id, p)| (id.as_str(), p.trust_score))
            .collect();
        pairs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        pairs.truncate(n);
        pairs
    }

    pub fn agent_count(&self) -> usize {
        self.profiles.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize_and_trust_score() {
        let mut engine = AgentTrustEngine::new(0.01, 0.05);
        engine.initialize_agent("a1", 0.8, 1000);
        let score = engine.trust_score("a1").unwrap();
        // trust = 0.8*0.4 + 1.0*0.35 + 0.8*0.25 = 0.32 + 0.35 + 0.20 = 0.87
        assert!((score - 0.87).abs() < f64::EPSILON);
    }

    #[test]
    fn test_record_success_increases_trust() {
        let mut engine = AgentTrustEngine::new(0.01, 0.05);
        engine.initialize_agent("a1", 0.5, 1000);
        let before = engine.trust_score("a1").unwrap();
        engine.record_success("a1", 2000);
        let after = engine.trust_score("a1").unwrap();
        assert!(after > before);
    }

    #[test]
    fn test_record_violation_decreases_trust() {
        let mut engine = AgentTrustEngine::new(0.01, 0.05);
        engine.initialize_agent("a1", 0.8, 1000);
        let before = engine.trust_score("a1").unwrap();
        engine.record_violation("a1", 2000);
        let after = engine.trust_score("a1").unwrap();
        assert!(after < before);
        assert_eq!(engine.get_profile("a1").unwrap().violations, 1);
    }

    #[test]
    fn test_record_cooperation_affects_score() {
        let mut engine = AgentTrustEngine::new(0.01, 0.05);
        engine.initialize_agent("a1", 0.5, 1000);
        let before = engine.trust_score("a1").unwrap();
        engine.record_cooperation("a1", true, 2000);
        let after = engine.trust_score("a1").unwrap();
        assert!(after > before);
    }

    #[test]
    fn test_apply_decay_reduces_scores() {
        let mut engine = AgentTrustEngine::new(0.01, 0.05);
        engine.initialize_agent("a1", 0.8, 1000);
        let before = engine.trust_score("a1").unwrap();
        // Advance 10 hours (36_000_000 ms)
        engine.apply_decay(1000 + 36_000_000);
        let after = engine.trust_score("a1").unwrap();
        assert!(after < before);
    }

    #[test]
    fn test_agents_above_threshold() {
        let mut engine = AgentTrustEngine::new(0.01, 0.05);
        engine.initialize_agent("a1", 0.9, 1000);
        engine.initialize_agent("a2", 0.1, 1000);
        // a1: 0.9*0.4 + 1.0*0.35 + 0.9*0.25 = 0.36+0.35+0.225 = 0.935
        // a2: 0.1*0.4 + 1.0*0.35 + 0.1*0.25 = 0.04+0.35+0.025 = 0.415
        let above = engine.agents_above_threshold(0.5);
        assert_eq!(above.len(), 1);
    }

    #[test]
    fn test_least_trusted() {
        let mut engine = AgentTrustEngine::new(0.01, 0.05);
        engine.initialize_agent("a1", 0.9, 1000);
        engine.initialize_agent("a2", 0.3, 1000);
        engine.initialize_agent("a3", 0.5, 1000);
        let least = engine.least_trusted(2);
        assert_eq!(least.len(), 2);
        assert!(least[0].1 <= least[1].1);
    }

    #[test]
    fn test_most_trusted() {
        let mut engine = AgentTrustEngine::new(0.01, 0.05);
        engine.initialize_agent("a1", 0.9, 1000);
        engine.initialize_agent("a2", 0.3, 1000);
        engine.initialize_agent("a3", 0.5, 1000);
        let most = engine.most_trusted(2);
        assert_eq!(most.len(), 2);
        assert!(most[0].1 >= most[1].1);
    }
}
