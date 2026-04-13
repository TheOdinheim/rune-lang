// ═══════════════════════════════════════════════════════════════════════
// Config — Framework-level configuration with environment presets
// and validation.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

// ── Environment ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Environment {
    Development,
    Testing,
    Staging,
    Production,
    AirGapped,
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── ConfigSeverity ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConfigSeverity {
    Info,
    Warning,
    Error,
}

impl fmt::Display for ConfigSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── ConfigValidation ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigValidation {
    pub field: String,
    pub message: String,
    pub severity: ConfigSeverity,
}

impl fmt::Display for ConfigValidation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.field, self.message)
    }
}

// ── FrameworkConfig ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkConfig {
    pub environment: Environment,
    pub fail_closed: bool,
    pub audit_enabled: bool,
    pub max_pipeline_stages: usize,
    pub default_timeout_ms: u64,
    pub risk_threshold: f64,
    pub min_trust_score: f64,
    pub require_identity: bool,
    pub allow_dry_run: bool,
    pub max_stale_heartbeat_seconds: i64,
}

impl FrameworkConfig {
    pub fn production() -> Self {
        Self {
            environment: Environment::Production,
            fail_closed: true,
            audit_enabled: true,
            max_pipeline_stages: 20,
            default_timeout_ms: 5000,
            risk_threshold: 0.7,
            min_trust_score: 0.6,
            require_identity: true,
            allow_dry_run: false,
            max_stale_heartbeat_seconds: 300,
        }
    }

    pub fn development() -> Self {
        Self {
            environment: Environment::Development,
            fail_closed: false,
            audit_enabled: true,
            max_pipeline_stages: 50,
            default_timeout_ms: 30000,
            risk_threshold: 0.9,
            min_trust_score: 0.0,
            require_identity: false,
            allow_dry_run: true,
            max_stale_heartbeat_seconds: 3600,
        }
    }

    pub fn air_gapped() -> Self {
        Self {
            environment: Environment::AirGapped,
            fail_closed: true,
            audit_enabled: true,
            max_pipeline_stages: 20,
            default_timeout_ms: 10000,
            risk_threshold: 0.5,
            min_trust_score: 0.8,
            require_identity: true,
            allow_dry_run: false,
            max_stale_heartbeat_seconds: 60,
        }
    }

    pub fn testing() -> Self {
        Self {
            environment: Environment::Testing,
            fail_closed: false,
            audit_enabled: false,
            max_pipeline_stages: 100,
            default_timeout_ms: 60000,
            risk_threshold: 1.0,
            min_trust_score: 0.0,
            require_identity: false,
            allow_dry_run: true,
            max_stale_heartbeat_seconds: 86400,
        }
    }

    pub fn validate(&self) -> Vec<ConfigValidation> {
        let mut issues = Vec::new();

        if self.risk_threshold <= 0.0 || self.risk_threshold > 1.0 {
            issues.push(ConfigValidation {
                field: "risk_threshold".into(),
                message: format!(
                    "Risk threshold {} is out of range (0.0, 1.0]",
                    self.risk_threshold
                ),
                severity: ConfigSeverity::Error,
            });
        }

        if self.min_trust_score < 0.0 || self.min_trust_score > 1.0 {
            issues.push(ConfigValidation {
                field: "min_trust_score".into(),
                message: format!(
                    "Minimum trust score {} is out of range [0.0, 1.0]",
                    self.min_trust_score
                ),
                severity: ConfigSeverity::Error,
            });
        }

        if self.default_timeout_ms == 0 {
            issues.push(ConfigValidation {
                field: "default_timeout_ms".into(),
                message: "Timeout must be > 0".into(),
                severity: ConfigSeverity::Error,
            });
        }

        if self.max_pipeline_stages == 0 {
            issues.push(ConfigValidation {
                field: "max_pipeline_stages".into(),
                message: "Max pipeline stages must be > 0".into(),
                severity: ConfigSeverity::Error,
            });
        }

        if self.environment == Environment::Production && !self.fail_closed {
            issues.push(ConfigValidation {
                field: "fail_closed".into(),
                message: "Production should use fail-closed semantics".into(),
                severity: ConfigSeverity::Warning,
            });
        }

        if self.environment == Environment::Production && !self.audit_enabled {
            issues.push(ConfigValidation {
                field: "audit_enabled".into(),
                message: "Production should have audit enabled".into(),
                severity: ConfigSeverity::Warning,
            });
        }

        if self.environment == Environment::Production && !self.require_identity {
            issues.push(ConfigValidation {
                field: "require_identity".into(),
                message: "Production should require identity verification".into(),
                severity: ConfigSeverity::Warning,
            });
        }

        if self.environment == Environment::AirGapped && self.allow_dry_run {
            issues.push(ConfigValidation {
                field: "allow_dry_run".into(),
                message: "Air-gapped environments should not allow dry-run".into(),
                severity: ConfigSeverity::Warning,
            });
        }

        issues
    }

    pub fn has_errors(&self) -> bool {
        self.validate()
            .iter()
            .any(|v| v.severity == ConfigSeverity::Error)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_display() {
        assert_eq!(Environment::Development.to_string(), "Development");
        assert_eq!(Environment::Testing.to_string(), "Testing");
        assert_eq!(Environment::Staging.to_string(), "Staging");
        assert_eq!(Environment::Production.to_string(), "Production");
        assert_eq!(Environment::AirGapped.to_string(), "AirGapped");
    }

    #[test]
    fn test_production_preset() {
        let cfg = FrameworkConfig::production();
        assert_eq!(cfg.environment, Environment::Production);
        assert!(cfg.fail_closed);
        assert!(cfg.audit_enabled);
        assert!(cfg.require_identity);
        assert!(!cfg.allow_dry_run);
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn test_development_preset() {
        let cfg = FrameworkConfig::development();
        assert_eq!(cfg.environment, Environment::Development);
        assert!(!cfg.fail_closed);
        assert!(cfg.allow_dry_run);
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn test_air_gapped_preset() {
        let cfg = FrameworkConfig::air_gapped();
        assert_eq!(cfg.environment, Environment::AirGapped);
        assert!(cfg.fail_closed);
        assert!(cfg.require_identity);
        assert!((cfg.min_trust_score - 0.8).abs() < f64::EPSILON);
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn test_testing_preset() {
        let cfg = FrameworkConfig::testing();
        assert_eq!(cfg.environment, Environment::Testing);
        assert!(!cfg.audit_enabled);
        assert!(cfg.allow_dry_run);
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn test_validate_bad_risk_threshold() {
        let mut cfg = FrameworkConfig::testing();
        cfg.risk_threshold = 0.0;
        let issues = cfg.validate();
        assert!(issues.iter().any(|v| v.field == "risk_threshold"));
        assert!(cfg.has_errors());
    }

    #[test]
    fn test_validate_bad_trust_score() {
        let mut cfg = FrameworkConfig::testing();
        cfg.min_trust_score = -0.1;
        let issues = cfg.validate();
        assert!(issues.iter().any(|v| v.field == "min_trust_score"));
    }

    #[test]
    fn test_validate_zero_timeout() {
        let mut cfg = FrameworkConfig::testing();
        cfg.default_timeout_ms = 0;
        assert!(cfg.has_errors());
    }

    #[test]
    fn test_validate_production_warnings() {
        let mut cfg = FrameworkConfig::production();
        cfg.fail_closed = false;
        cfg.audit_enabled = false;
        cfg.require_identity = false;
        let issues = cfg.validate();
        let warnings: Vec<_> = issues
            .iter()
            .filter(|v| v.severity == ConfigSeverity::Warning)
            .collect();
        assert_eq!(warnings.len(), 3);
    }

    #[test]
    fn test_config_validation_display() {
        let v = ConfigValidation {
            field: "timeout".into(),
            message: "too low".into(),
            severity: ConfigSeverity::Error,
        };
        assert_eq!(v.to_string(), "[Error] timeout: too low");
    }

    #[test]
    fn test_config_severity_ordering() {
        assert!(ConfigSeverity::Info < ConfigSeverity::Warning);
        assert!(ConfigSeverity::Warning < ConfigSeverity::Error);
    }
}
