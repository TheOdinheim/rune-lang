// ═══════════════════════════════════════════════════════════════════════
// Evaluation Context
//
// Carries environmental data that conditions check against:
// who, when, where, risk level, MFA status, custom attributes.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::types::Subject;

/// Environment for evaluating permission conditions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalContext {
    pub subject: Subject,
    pub timestamp: i64,
    pub source_ip: Option<String>,
    pub risk_score: Option<i64>,
    pub mfa_verified: bool,
    pub session_id: Option<String>,
    pub device_id: Option<String>,
    pub location: Option<String>,
    pub custom: HashMap<String, String>,
}

/// Builder for EvalContext.
pub struct EvalContextBuilder {
    subject: Subject,
    timestamp: i64,
    source_ip: Option<String>,
    risk_score: Option<i64>,
    mfa_verified: bool,
    session_id: Option<String>,
    device_id: Option<String>,
    location: Option<String>,
    custom: HashMap<String, String>,
}

impl EvalContext {
    pub fn for_subject(subject: Subject) -> EvalContextBuilder {
        EvalContextBuilder {
            subject,
            timestamp: 0,
            source_ip: None,
            risk_score: None,
            mfa_verified: false,
            session_id: None,
            device_id: None,
            location: None,
            custom: HashMap::new(),
        }
    }
}

impl EvalContextBuilder {
    pub fn timestamp(mut self, ts: i64) -> Self {
        self.timestamp = ts;
        self
    }

    pub fn source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }

    pub fn risk_score(mut self, score: i64) -> Self {
        self.risk_score = Some(score);
        self
    }

    pub fn mfa(mut self, verified: bool) -> Self {
        self.mfa_verified = verified;
        self
    }

    pub fn session_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    pub fn device_id(mut self, id: impl Into<String>) -> Self {
        self.device_id = Some(id.into());
        self
    }

    pub fn location(mut self, loc: impl Into<String>) -> Self {
        self.location = Some(loc.into());
        self
    }

    pub fn custom(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom.insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> EvalContext {
        EvalContext {
            subject: self.subject,
            timestamp: self.timestamp,
            source_ip: self.source_ip,
            risk_score: self.risk_score,
            mfa_verified: self.mfa_verified,
            session_id: self.session_id,
            device_id: self.device_id,
            location: self.location,
            custom: self.custom,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SubjectType, ClassificationLevel};

    fn test_subject() -> Subject {
        Subject::new("user1", SubjectType::User, "Alice")
            .clearance(ClassificationLevel::Confidential)
    }

    #[test]
    fn test_builder_defaults() {
        let ctx = EvalContext::for_subject(test_subject()).build();
        assert_eq!(ctx.timestamp, 0);
        assert!(ctx.source_ip.is_none());
        assert!(ctx.risk_score.is_none());
        assert!(!ctx.mfa_verified);
        assert!(ctx.session_id.is_none());
        assert!(ctx.custom.is_empty());
    }

    #[test]
    fn test_builder_full() {
        let ctx = EvalContext::for_subject(test_subject())
            .timestamp(12345)
            .source_ip("10.0.0.1")
            .risk_score(25)
            .mfa(true)
            .session_id("sess-1")
            .device_id("dev-1")
            .location("us-east-1")
            .custom("team", "security")
            .build();
        assert_eq!(ctx.timestamp, 12345);
        assert_eq!(ctx.source_ip, Some("10.0.0.1".into()));
        assert_eq!(ctx.risk_score, Some(25));
        assert!(ctx.mfa_verified);
        assert_eq!(ctx.session_id, Some("sess-1".into()));
        assert_eq!(ctx.device_id, Some("dev-1".into()));
        assert_eq!(ctx.location, Some("us-east-1".into()));
        assert_eq!(ctx.custom.get("team"), Some(&"security".to_string()));
    }
}
