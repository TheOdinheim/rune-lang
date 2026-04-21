// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — EmergencyShutdownController trait for managing system
// transitions from unsafe states to safe states. Shutdown is auditable,
// irreversible without explicit reauthorization, and independent of
// the system being shut down.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::backend::ShutdownType;
use crate::error::SafetyError;

// ── ShutdownHandle ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShutdownHandle(pub String);

impl ShutdownHandle {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for ShutdownHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── ShutdownStatus ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShutdownStatus {
    Initiated,
    InProgress { progress_description: String },
    Completed { completed_at: i64 },
    Failed { reason: String },
    Reauthorized { by: String, at: i64 },
}

impl fmt::Display for ShutdownStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initiated => f.write_str("Initiated"),
            Self::InProgress { .. } => f.write_str("InProgress"),
            Self::Completed { completed_at } => write!(f, "Completed(at={completed_at})"),
            Self::Failed { reason } => write!(f, "Failed({reason})"),
            Self::Reauthorized { by, at } => write!(f, "Reauthorized(by={by}, at={at})"),
        }
    }
}

// ── ShutdownEntry ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
struct ShutdownEntry {
    handle: ShutdownHandle,
    system_id: String,
    trigger_reason: String,
    shutdown_type: ShutdownType,
    status: ShutdownStatus,
    initiated_at: i64,
}

// ── EmergencyShutdownController trait ───────────────────────────────

pub trait EmergencyShutdownController {
    fn initiate_shutdown(
        &mut self,
        system_id: &str,
        trigger_reason: &str,
        shutdown_type: ShutdownType,
    ) -> Result<ShutdownHandle, SafetyError>;

    fn check_shutdown_status(
        &self,
        handle: &ShutdownHandle,
    ) -> Result<ShutdownStatus, SafetyError>;

    fn request_reauthorization(
        &mut self,
        handle: &ShutdownHandle,
        reauthorizer: &str,
    ) -> Result<bool, SafetyError>;

    fn list_active_shutdowns(&self) -> Vec<ShutdownHandle>;

    fn list_shutdown_history_for_system(&self, system_id: &str) -> Vec<ShutdownHandle>;

    fn controller_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryEmergencyShutdownController ─────────────────────────────

pub struct InMemoryEmergencyShutdownController {
    id: String,
    entries: HashMap<String, ShutdownEntry>,
    counter: u64,
}

impl InMemoryEmergencyShutdownController {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            entries: HashMap::new(),
            counter: 0,
        }
    }
}

impl EmergencyShutdownController for InMemoryEmergencyShutdownController {
    fn initiate_shutdown(
        &mut self,
        system_id: &str,
        trigger_reason: &str,
        shutdown_type: ShutdownType,
    ) -> Result<ShutdownHandle, SafetyError> {
        self.counter += 1;
        let handle = ShutdownHandle::new(format!("sd-{}", self.counter));
        // Immediate completion for testing
        let status = ShutdownStatus::Completed {
            completed_at: 0,
        };
        self.entries.insert(
            handle.0.clone(),
            ShutdownEntry {
                handle: handle.clone(),
                system_id: system_id.to_string(),
                trigger_reason: trigger_reason.to_string(),
                shutdown_type,
                status,
                initiated_at: 0,
            },
        );
        Ok(handle)
    }

    fn check_shutdown_status(
        &self,
        handle: &ShutdownHandle,
    ) -> Result<ShutdownStatus, SafetyError> {
        self.entries
            .get(&handle.0)
            .map(|e| e.status.clone())
            .ok_or_else(|| {
                SafetyError::InvalidOperation(format!("shutdown not found: {}", handle.0))
            })
    }

    fn request_reauthorization(
        &mut self,
        handle: &ShutdownHandle,
        reauthorizer: &str,
    ) -> Result<bool, SafetyError> {
        let entry = self
            .entries
            .get_mut(&handle.0)
            .ok_or_else(|| {
                SafetyError::InvalidOperation(format!("shutdown not found: {}", handle.0))
            })?;
        entry.status = ShutdownStatus::Reauthorized {
            by: reauthorizer.to_string(),
            at: 0,
        };
        Ok(true)
    }

    fn list_active_shutdowns(&self) -> Vec<ShutdownHandle> {
        self.entries
            .values()
            .filter(|e| {
                matches!(
                    e.status,
                    ShutdownStatus::Initiated | ShutdownStatus::InProgress { .. }
                )
            })
            .map(|e| e.handle.clone())
            .collect()
    }

    fn list_shutdown_history_for_system(&self, system_id: &str) -> Vec<ShutdownHandle> {
        self.entries
            .values()
            .filter(|e| e.system_id == system_id)
            .map(|e| e.handle.clone())
            .collect()
    }

    fn controller_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── AuditedEmergencyShutdownController ──────────────────────────────

pub struct AuditedEmergencyShutdownController<C: EmergencyShutdownController> {
    inner: C,
    id: String,
    audit_log: Vec<String>,
}

impl<C: EmergencyShutdownController> AuditedEmergencyShutdownController<C> {
    pub fn new(inner: C, id: impl Into<String>) -> Self {
        Self {
            inner,
            id: id.into(),
            audit_log: Vec::new(),
        }
    }

    pub fn audit_entries(&self) -> &[String] {
        &self.audit_log
    }
}

impl<C: EmergencyShutdownController> EmergencyShutdownController
    for AuditedEmergencyShutdownController<C>
{
    fn initiate_shutdown(
        &mut self,
        system_id: &str,
        trigger_reason: &str,
        shutdown_type: ShutdownType,
    ) -> Result<ShutdownHandle, SafetyError> {
        let handle = self
            .inner
            .initiate_shutdown(system_id, trigger_reason, shutdown_type.clone())?;
        self.audit_log.push(format!(
            "SHUTDOWN_INITIATED: system={}, reason={}, type={}, handle={}",
            system_id, trigger_reason, shutdown_type, handle
        ));
        Ok(handle)
    }

    fn check_shutdown_status(
        &self,
        handle: &ShutdownHandle,
    ) -> Result<ShutdownStatus, SafetyError> {
        self.inner.check_shutdown_status(handle)
    }

    fn request_reauthorization(
        &mut self,
        handle: &ShutdownHandle,
        reauthorizer: &str,
    ) -> Result<bool, SafetyError> {
        let granted = self.inner.request_reauthorization(handle, reauthorizer)?;
        self.audit_log.push(format!(
            "REAUTHORIZATION_{}: handle={}, by={}",
            if granted { "GRANTED" } else { "DENIED" },
            handle,
            reauthorizer
        ));
        Ok(granted)
    }

    fn list_active_shutdowns(&self) -> Vec<ShutdownHandle> {
        self.inner.list_active_shutdowns()
    }

    fn list_shutdown_history_for_system(&self, system_id: &str) -> Vec<ShutdownHandle> {
        self.inner.list_shutdown_history_for_system(system_id)
    }

    fn controller_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.inner.is_active()
    }
}

// ── NullEmergencyShutdownController ─────────────────────────────────

pub struct NullEmergencyShutdownController;

impl EmergencyShutdownController for NullEmergencyShutdownController {
    fn initiate_shutdown(
        &mut self,
        _system_id: &str,
        _trigger_reason: &str,
        _shutdown_type: ShutdownType,
    ) -> Result<ShutdownHandle, SafetyError> {
        Ok(ShutdownHandle::new("null-sd"))
    }

    fn check_shutdown_status(
        &self,
        _handle: &ShutdownHandle,
    ) -> Result<ShutdownStatus, SafetyError> {
        Ok(ShutdownStatus::Initiated)
    }

    fn request_reauthorization(
        &mut self,
        _handle: &ShutdownHandle,
        _reauthorizer: &str,
    ) -> Result<bool, SafetyError> {
        Ok(false)
    }

    fn list_active_shutdowns(&self) -> Vec<ShutdownHandle> {
        Vec::new()
    }

    fn list_shutdown_history_for_system(&self, _system_id: &str) -> Vec<ShutdownHandle> {
        Vec::new()
    }

    fn controller_id(&self) -> &str {
        "null-shutdown-controller"
    }

    fn is_active(&self) -> bool {
        false
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initiate_shutdown() {
        let mut ctrl = InMemoryEmergencyShutdownController::new("c1");
        let handle = ctrl
            .initiate_shutdown("sys-1", "violation", ShutdownType::EmergencyImmediate)
            .unwrap();
        assert!(!handle.0.is_empty());
    }

    #[test]
    fn test_check_status() {
        let mut ctrl = InMemoryEmergencyShutdownController::new("c1");
        let handle = ctrl
            .initiate_shutdown("sys-1", "violation", ShutdownType::EmergencyImmediate)
            .unwrap();
        let status = ctrl.check_shutdown_status(&handle).unwrap();
        assert!(matches!(status, ShutdownStatus::Completed { .. }));
    }

    #[test]
    fn test_reauthorization() {
        let mut ctrl = InMemoryEmergencyShutdownController::new("c1");
        let handle = ctrl
            .initiate_shutdown("sys-1", "violation", ShutdownType::EmergencyImmediate)
            .unwrap();
        let granted = ctrl.request_reauthorization(&handle, "admin").unwrap();
        assert!(granted);
        let status = ctrl.check_shutdown_status(&handle).unwrap();
        assert!(matches!(status, ShutdownStatus::Reauthorized { .. }));
    }

    #[test]
    fn test_list_shutdown_history() {
        let mut ctrl = InMemoryEmergencyShutdownController::new("c1");
        ctrl.initiate_shutdown("sys-1", "r1", ShutdownType::EmergencyImmediate)
            .unwrap();
        ctrl.initiate_shutdown("sys-1", "r2", ShutdownType::GracefulDegradation)
            .unwrap();
        ctrl.initiate_shutdown("sys-2", "r3", ShutdownType::ManualOverride)
            .unwrap();
        assert_eq!(ctrl.list_shutdown_history_for_system("sys-1").len(), 2);
        assert_eq!(ctrl.list_shutdown_history_for_system("sys-2").len(), 1);
    }

    #[test]
    fn test_active_shutdowns_empty_when_completed() {
        let mut ctrl = InMemoryEmergencyShutdownController::new("c1");
        ctrl.initiate_shutdown("sys-1", "r", ShutdownType::EmergencyImmediate)
            .unwrap();
        // InMemory completes immediately, so no active shutdowns
        assert!(ctrl.list_active_shutdowns().is_empty());
    }

    #[test]
    fn test_audited_wrapper() {
        let inner = InMemoryEmergencyShutdownController::new("inner");
        let mut ctrl = AuditedEmergencyShutdownController::new(inner, "audited");
        let handle = ctrl
            .initiate_shutdown("sys-1", "violation", ShutdownType::EmergencyImmediate)
            .unwrap();
        ctrl.request_reauthorization(&handle, "admin").unwrap();
        assert_eq!(ctrl.audit_entries().len(), 2);
        assert!(ctrl.audit_entries()[0].contains("SHUTDOWN_INITIATED"));
        assert!(ctrl.audit_entries()[1].contains("REAUTHORIZATION_GRANTED"));
    }

    #[test]
    fn test_audited_controller_id() {
        let inner = InMemoryEmergencyShutdownController::new("inner");
        let ctrl = AuditedEmergencyShutdownController::new(inner, "audited");
        assert_eq!(ctrl.controller_id(), "audited");
        assert!(ctrl.is_active());
    }

    #[test]
    fn test_null_controller() {
        let mut ctrl = NullEmergencyShutdownController;
        assert!(!ctrl.is_active());
        let handle = ctrl
            .initiate_shutdown("s", "r", ShutdownType::EmergencyImmediate)
            .unwrap();
        assert_eq!(
            ctrl.check_shutdown_status(&handle).unwrap(),
            ShutdownStatus::Initiated
        );
        assert!(!ctrl.request_reauthorization(&handle, "admin").unwrap());
    }

    #[test]
    fn test_shutdown_status_display() {
        assert!(!ShutdownStatus::Initiated.to_string().is_empty());
        assert!(!ShutdownStatus::InProgress {
            progress_description: "x".into()
        }
        .to_string()
        .is_empty());
        assert!(!ShutdownStatus::Completed { completed_at: 0 }
            .to_string()
            .is_empty());
        assert!(!ShutdownStatus::Failed { reason: "r".into() }
            .to_string()
            .is_empty());
        assert!(!ShutdownStatus::Reauthorized {
            by: "a".into(),
            at: 0
        }
        .to_string()
        .is_empty());
    }

    #[test]
    fn test_shutdown_handle_display() {
        let h = ShutdownHandle::new("sd-123");
        assert_eq!(h.to_string(), "sd-123");
    }

    #[test]
    fn test_check_missing_handle() {
        let ctrl = InMemoryEmergencyShutdownController::new("c1");
        assert!(ctrl
            .check_shutdown_status(&ShutdownHandle::new("missing"))
            .is_err());
    }
}
