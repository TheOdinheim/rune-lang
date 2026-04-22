// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Data access evaluation. Evaluates DataAccessRequest
// against DataAccessPolicy, checking role, operation, sensitivity
// level, and purpose declaration requirements.
// ═══════════════════════════════════════════════════════════════════════

use crate::access::{DataAccessDecision, DataAccessPolicy, DataAccessRequest};
use crate::classification::DataSensitivity;

// ── AccessCheck ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessCheck {
    pub check_name: String,
    pub passed: bool,
    pub details: String,
}

// ── AccessEvaluationReport ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessEvaluationReport {
    pub request_id: String,
    pub dataset_ref: String,
    pub decision: DataAccessDecision,
    pub checks_performed: Vec<AccessCheck>,
    pub evaluated_at: i64,
}

// ── DataAccessEvaluator ──────────────────────────────────────────────

pub struct DataAccessEvaluator;

impl DataAccessEvaluator {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate_access(
        &self,
        request: &DataAccessRequest,
        policy: &DataAccessPolicy,
        dataset_sensitivity: Option<&DataSensitivity>,
        evaluated_at: i64,
    ) -> AccessEvaluationReport {
        let mut checks = Vec::new();

        let role_check = self.check_role(&request.requester_role, policy);
        checks.push(role_check.clone());
        if !role_check.passed {
            return AccessEvaluationReport {
                request_id: request.request_id.clone(),
                dataset_ref: request.dataset_ref.clone(),
                decision: DataAccessDecision::Denied { reason: role_check.details.clone() },
                checks_performed: checks,
                evaluated_at,
            };
        }

        let op_check = self.check_operation(&request.operation, policy);
        checks.push(op_check.clone());
        if !op_check.passed {
            return AccessEvaluationReport {
                request_id: request.request_id.clone(),
                dataset_ref: request.dataset_ref.clone(),
                decision: DataAccessDecision::Denied { reason: op_check.details.clone() },
                checks_performed: checks,
                evaluated_at,
            };
        }

        if let Some(sensitivity) = dataset_sensitivity {
            let sens_check = self.check_sensitivity(sensitivity, policy);
            checks.push(sens_check.clone());
            if !sens_check.passed {
                return AccessEvaluationReport {
                    request_id: request.request_id.clone(),
                    dataset_ref: request.dataset_ref.clone(),
                    decision: DataAccessDecision::Denied { reason: sens_check.details.clone() },
                    checks_performed: checks,
                    evaluated_at,
                };
            }
        }

        let purpose_check = self.check_purpose(&request.purpose, policy);
        checks.push(purpose_check.clone());
        if !purpose_check.passed {
            return AccessEvaluationReport {
                request_id: request.request_id.clone(),
                dataset_ref: request.dataset_ref.clone(),
                decision: DataAccessDecision::Denied { reason: purpose_check.details.clone() },
                checks_performed: checks,
                evaluated_at,
            };
        }

        let decision = if policy.require_audit {
            DataAccessDecision::ConditionalGrant {
                conditions: vec!["Access will be audited".to_string()],
                reason: "All checks passed — audit required".to_string(),
            }
        } else {
            DataAccessDecision::Granted {
                reason: "All checks passed".to_string(),
            }
        };

        AccessEvaluationReport {
            request_id: request.request_id.clone(),
            dataset_ref: request.dataset_ref.clone(),
            decision,
            checks_performed: checks,
            evaluated_at,
        }
    }

    pub fn check_role(&self, requester_role: &str, policy: &DataAccessPolicy) -> AccessCheck {
        if policy.denied_roles.contains(&requester_role.to_string()) {
            return AccessCheck {
                check_name: "role_check".into(),
                passed: false,
                details: format!("Role '{requester_role}' is explicitly denied"),
            };
        }
        if !policy.allowed_roles.is_empty()
            && !policy.allowed_roles.contains(&requester_role.to_string())
        {
            return AccessCheck {
                check_name: "role_check".into(),
                passed: false,
                details: format!("Role '{requester_role}' is not in allowed roles"),
            };
        }
        AccessCheck {
            check_name: "role_check".into(),
            passed: true,
            details: format!("Role '{requester_role}' is permitted"),
        }
    }

    pub fn check_operation(
        &self,
        operation: &crate::access::DataOperation,
        policy: &DataAccessPolicy,
    ) -> AccessCheck {
        if policy.allowed_operations.contains(operation) {
            AccessCheck {
                check_name: "operation_check".into(),
                passed: true,
                details: format!("Operation '{}' is permitted", operation),
            }
        } else {
            AccessCheck {
                check_name: "operation_check".into(),
                passed: false,
                details: format!("Operation '{}' is not in allowed operations", operation),
            }
        }
    }

    pub fn check_sensitivity(
        &self,
        dataset_sensitivity: &DataSensitivity,
        policy: &DataAccessPolicy,
    ) -> AccessCheck {
        match &policy.max_sensitivity_level {
            Some(max) if dataset_sensitivity > max => AccessCheck {
                check_name: "sensitivity_check".into(),
                passed: false,
                details: format!(
                    "Dataset sensitivity '{}' exceeds maximum allowed '{}'",
                    dataset_sensitivity, max
                ),
            },
            _ => AccessCheck {
                check_name: "sensitivity_check".into(),
                passed: true,
                details: "Sensitivity level within allowed range".to_string(),
            },
        }
    }

    pub fn check_purpose(
        &self,
        purpose: &Option<String>,
        policy: &DataAccessPolicy,
    ) -> AccessCheck {
        if policy.require_purpose_declaration {
            match purpose {
                Some(p) if !p.is_empty() => AccessCheck {
                    check_name: "purpose_check".into(),
                    passed: true,
                    details: "Purpose declared".to_string(),
                },
                _ => AccessCheck {
                    check_name: "purpose_check".into(),
                    passed: false,
                    details: "Purpose declaration required but not provided".to_string(),
                },
            }
        } else {
            AccessCheck {
                check_name: "purpose_check".into(),
                passed: true,
                details: "Purpose declaration not required".to_string(),
            }
        }
    }
}

impl Default for DataAccessEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::DataOperation;
    use std::collections::HashMap;

    fn make_policy() -> DataAccessPolicy {
        DataAccessPolicy {
            policy_id: "dap-1".into(),
            dataset_ref: "ds-users".into(),
            allowed_roles: vec!["analyst".into(), "engineer".into()],
            denied_roles: vec!["intern".into()],
            allowed_operations: vec![DataOperation::Read, DataOperation::Transform],
            require_purpose_declaration: false,
            require_audit: false,
            max_sensitivity_level: Some(DataSensitivity::Confidential),
            created_at: 1000,
            metadata: HashMap::new(),
        }
    }

    fn make_request(role: &str, op: DataOperation) -> DataAccessRequest {
        DataAccessRequest {
            request_id: "dar-1".into(),
            requester_id: "user-1".into(),
            requester_role: role.into(),
            dataset_ref: "ds-users".into(),
            operation: op,
            purpose: Some("analysis".into()),
            requested_at: 2000,
            context: HashMap::new(),
        }
    }

    #[test]
    fn test_allowed_role_allowed_op() {
        let evaluator = DataAccessEvaluator::new();
        let report = evaluator.evaluate_access(
            &make_request("analyst", DataOperation::Read),
            &make_policy(),
            None,
            3000,
        );
        assert!(matches!(report.decision, DataAccessDecision::Granted { .. }));
    }

    #[test]
    fn test_denied_role() {
        let evaluator = DataAccessEvaluator::new();
        let report = evaluator.evaluate_access(
            &make_request("intern", DataOperation::Read),
            &make_policy(),
            None,
            3000,
        );
        assert!(matches!(report.decision, DataAccessDecision::Denied { .. }));
    }

    #[test]
    fn test_disallowed_operation() {
        let evaluator = DataAccessEvaluator::new();
        let report = evaluator.evaluate_access(
            &make_request("analyst", DataOperation::Delete),
            &make_policy(),
            None,
            3000,
        );
        assert!(matches!(report.decision, DataAccessDecision::Denied { .. }));
    }

    #[test]
    fn test_sensitivity_exceeds_max() {
        let evaluator = DataAccessEvaluator::new();
        let report = evaluator.evaluate_access(
            &make_request("analyst", DataOperation::Read),
            &make_policy(),
            Some(&DataSensitivity::Restricted), // exceeds Confidential max
            3000,
        );
        assert!(matches!(report.decision, DataAccessDecision::Denied { .. }));
    }

    #[test]
    fn test_sensitivity_within_max() {
        let evaluator = DataAccessEvaluator::new();
        let report = evaluator.evaluate_access(
            &make_request("analyst", DataOperation::Read),
            &make_policy(),
            Some(&DataSensitivity::Internal),
            3000,
        );
        assert!(matches!(report.decision, DataAccessDecision::Granted { .. }));
    }

    #[test]
    fn test_missing_purpose_when_required() {
        let evaluator = DataAccessEvaluator::new();
        let mut policy = make_policy();
        policy.require_purpose_declaration = true;
        let mut request = make_request("analyst", DataOperation::Read);
        request.purpose = None;
        let report = evaluator.evaluate_access(&request, &policy, None, 3000);
        assert!(matches!(report.decision, DataAccessDecision::Denied { .. }));
    }

    #[test]
    fn test_purpose_provided_when_required() {
        let evaluator = DataAccessEvaluator::new();
        let mut policy = make_policy();
        policy.require_purpose_declaration = true;
        let report = evaluator.evaluate_access(
            &make_request("analyst", DataOperation::Read),
            &policy,
            None,
            3000,
        );
        assert!(matches!(report.decision, DataAccessDecision::Granted { .. }));
    }

    #[test]
    fn test_conditional_grant_when_audit_required() {
        let evaluator = DataAccessEvaluator::new();
        let mut policy = make_policy();
        policy.require_audit = true;
        let report = evaluator.evaluate_access(
            &make_request("analyst", DataOperation::Read),
            &policy,
            None,
            3000,
        );
        assert!(matches!(report.decision, DataAccessDecision::ConditionalGrant { .. }));
    }

    #[test]
    fn test_role_not_in_allowed_list() {
        let evaluator = DataAccessEvaluator::new();
        let report = evaluator.evaluate_access(
            &make_request("external_contractor", DataOperation::Read),
            &make_policy(),
            None,
            3000,
        );
        assert!(matches!(report.decision, DataAccessDecision::Denied { .. }));
    }

    #[test]
    fn test_checks_performed_count() {
        let evaluator = DataAccessEvaluator::new();
        let report = evaluator.evaluate_access(
            &make_request("analyst", DataOperation::Read),
            &make_policy(),
            Some(&DataSensitivity::Internal),
            3000,
        );
        // role + op + sensitivity + purpose = 4 checks
        assert_eq!(report.checks_performed.len(), 4);
    }

    #[test]
    fn test_evaluator_default() {
        let _e = DataAccessEvaluator;
    }
}
