// ═══════════════════════════════════════════════════════════════════════
// Registry — Component registry for tracking crate availability and
// system readiness.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::FrameworkError;

// ── ComponentId ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ComponentId(pub String);

impl ComponentId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for ComponentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── ComponentType ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComponentType {
    Identity,
    Permission,
    Secret,
    Privacy,
    Security,
    Detection,
    Shield,
    Monitoring,
    Provenance,
    Trust,
}

impl fmt::Display for ComponentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── ComponentStatus ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentStatus {
    Available,
    Degraded,
    Unavailable,
    Unknown,
}

impl fmt::Display for ComponentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── ComponentInfo ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentInfo {
    pub id: ComponentId,
    pub component_type: ComponentType,
    pub name: String,
    pub version: String,
    pub status: ComponentStatus,
    pub last_heartbeat: i64,
    pub metadata: HashMap<String, String>,
}

impl ComponentInfo {
    pub fn new(
        id: impl Into<String>,
        component_type: ComponentType,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            id: ComponentId::new(id),
            component_type,
            name: name.into(),
            version: version.into(),
            status: ComponentStatus::Available,
            last_heartbeat: 0,
            metadata: HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

// ── SystemReadiness ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemReadiness {
    pub total_components: usize,
    pub available: usize,
    pub degraded: usize,
    pub unavailable: usize,
    pub unknown: usize,
    pub is_ready: bool,
}

impl fmt::Display for SystemReadiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "System: {} ({}/{} available, {} degraded, {} unavailable)",
            if self.is_ready { "READY" } else { "NOT READY" },
            self.available,
            self.total_components,
            self.degraded,
            self.unavailable,
        )
    }
}

// ── ComponentRegistry ─────────────────────────────────────────────────

pub struct ComponentRegistry {
    components: HashMap<ComponentId, ComponentInfo>,
}

impl ComponentRegistry {
    pub fn new() -> Self {
        Self {
            components: HashMap::new(),
        }
    }

    pub fn register(&mut self, info: ComponentInfo) -> Result<(), FrameworkError> {
        if self.components.contains_key(&info.id) {
            return Err(FrameworkError::DuplicateComponent {
                component_id: info.id.0.clone(),
            });
        }
        self.components.insert(info.id.clone(), info);
        Ok(())
    }

    pub fn deregister(&mut self, id: &ComponentId) -> Result<ComponentInfo, FrameworkError> {
        self.components.remove(id).ok_or_else(|| FrameworkError::ComponentNotFound {
            component_id: id.0.clone(),
        })
    }

    pub fn get(&self, id: &ComponentId) -> Option<&ComponentInfo> {
        self.components.get(id)
    }

    pub fn heartbeat(&mut self, id: &ComponentId, timestamp: i64) -> Result<(), FrameworkError> {
        let info = self
            .components
            .get_mut(id)
            .ok_or_else(|| FrameworkError::ComponentNotFound {
                component_id: id.0.clone(),
            })?;
        info.last_heartbeat = timestamp;
        Ok(())
    }

    pub fn update_status(
        &mut self,
        id: &ComponentId,
        status: ComponentStatus,
    ) -> Result<(), FrameworkError> {
        let info = self
            .components
            .get_mut(id)
            .ok_or_else(|| FrameworkError::ComponentNotFound {
                component_id: id.0.clone(),
            })?;
        info.status = status;
        Ok(())
    }

    pub fn by_type(&self, component_type: ComponentType) -> Vec<&ComponentInfo> {
        self.components
            .values()
            .filter(|c| c.component_type == component_type)
            .collect()
    }

    pub fn available_components(&self) -> Vec<&ComponentInfo> {
        self.components
            .values()
            .filter(|c| c.status == ComponentStatus::Available)
            .collect()
    }

    pub fn stale_components(&self, current_time: i64, max_age_seconds: i64) -> Vec<&ComponentInfo> {
        self.components
            .values()
            .filter(|c| {
                c.last_heartbeat > 0
                    && (current_time - c.last_heartbeat) > max_age_seconds
            })
            .collect()
    }

    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    pub fn system_readiness(&self) -> SystemReadiness {
        let total = self.components.len();
        let mut available = 0;
        let mut degraded = 0;
        let mut unavailable = 0;
        let mut unknown = 0;

        for info in self.components.values() {
            match info.status {
                ComponentStatus::Available => available += 1,
                ComponentStatus::Degraded => degraded += 1,
                ComponentStatus::Unavailable => unavailable += 1,
                ComponentStatus::Unknown => unknown += 1,
            }
        }

        let is_ready = unavailable == 0 && total > 0;

        SystemReadiness {
            total_components: total,
            available,
            degraded,
            unavailable,
            unknown,
            is_ready,
        }
    }
}

impl Default for ComponentRegistry {
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

    fn sample_component(id: &str, ct: ComponentType) -> ComponentInfo {
        ComponentInfo::new(id, ct, format!("{id}-name"), "1.0.0")
    }

    #[test]
    fn test_component_id_display() {
        let id = ComponentId::new("rune-security");
        assert_eq!(id.to_string(), "rune-security");
    }

    #[test]
    fn test_component_type_display_all() {
        let types = vec![
            ComponentType::Identity,
            ComponentType::Permission,
            ComponentType::Secret,
            ComponentType::Privacy,
            ComponentType::Security,
            ComponentType::Detection,
            ComponentType::Shield,
            ComponentType::Monitoring,
            ComponentType::Provenance,
            ComponentType::Trust,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 10);
    }

    #[test]
    fn test_component_status_display() {
        assert_eq!(ComponentStatus::Available.to_string(), "Available");
        assert_eq!(ComponentStatus::Degraded.to_string(), "Degraded");
        assert_eq!(ComponentStatus::Unavailable.to_string(), "Unavailable");
        assert_eq!(ComponentStatus::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_register_and_get() {
        let mut reg = ComponentRegistry::new();
        reg.register(sample_component("sec-1", ComponentType::Security))
            .unwrap();
        assert!(reg.get(&ComponentId::new("sec-1")).is_some());
        assert!(reg.get(&ComponentId::new("missing")).is_none());
        assert_eq!(reg.component_count(), 1);
    }

    #[test]
    fn test_duplicate_registration() {
        let mut reg = ComponentRegistry::new();
        reg.register(sample_component("sec-1", ComponentType::Security))
            .unwrap();
        let err = reg
            .register(sample_component("sec-1", ComponentType::Security))
            .unwrap_err();
        assert_eq!(
            err,
            FrameworkError::DuplicateComponent {
                component_id: "sec-1".into()
            }
        );
    }

    #[test]
    fn test_deregister() {
        let mut reg = ComponentRegistry::new();
        reg.register(sample_component("sec-1", ComponentType::Security))
            .unwrap();
        let info = reg.deregister(&ComponentId::new("sec-1")).unwrap();
        assert_eq!(info.id.0, "sec-1");
        assert_eq!(reg.component_count(), 0);
    }

    #[test]
    fn test_heartbeat() {
        let mut reg = ComponentRegistry::new();
        reg.register(sample_component("sec-1", ComponentType::Security))
            .unwrap();
        reg.heartbeat(&ComponentId::new("sec-1"), 1000).unwrap();
        assert_eq!(reg.get(&ComponentId::new("sec-1")).unwrap().last_heartbeat, 1000);
    }

    #[test]
    fn test_update_status() {
        let mut reg = ComponentRegistry::new();
        reg.register(sample_component("sec-1", ComponentType::Security))
            .unwrap();
        reg.update_status(&ComponentId::new("sec-1"), ComponentStatus::Degraded)
            .unwrap();
        assert_eq!(
            reg.get(&ComponentId::new("sec-1")).unwrap().status,
            ComponentStatus::Degraded
        );
    }

    #[test]
    fn test_by_type() {
        let mut reg = ComponentRegistry::new();
        reg.register(sample_component("sec-1", ComponentType::Security))
            .unwrap();
        reg.register(sample_component("sec-2", ComponentType::Security))
            .unwrap();
        reg.register(sample_component("det-1", ComponentType::Detection))
            .unwrap();
        assert_eq!(reg.by_type(ComponentType::Security).len(), 2);
        assert_eq!(reg.by_type(ComponentType::Detection).len(), 1);
        assert_eq!(reg.by_type(ComponentType::Identity).len(), 0);
    }

    #[test]
    fn test_available_components() {
        let mut reg = ComponentRegistry::new();
        reg.register(sample_component("sec-1", ComponentType::Security))
            .unwrap();
        reg.register(sample_component("sec-2", ComponentType::Security))
            .unwrap();
        reg.update_status(&ComponentId::new("sec-2"), ComponentStatus::Unavailable)
            .unwrap();
        assert_eq!(reg.available_components().len(), 1);
    }

    #[test]
    fn test_stale_components() {
        let mut reg = ComponentRegistry::new();
        reg.register(sample_component("sec-1", ComponentType::Security))
            .unwrap();
        reg.heartbeat(&ComponentId::new("sec-1"), 100).unwrap();
        assert_eq!(reg.stale_components(200, 60).len(), 1);
        assert_eq!(reg.stale_components(150, 60).len(), 0);
    }

    #[test]
    fn test_system_readiness_ready() {
        let mut reg = ComponentRegistry::new();
        reg.register(sample_component("sec-1", ComponentType::Security))
            .unwrap();
        reg.register(sample_component("det-1", ComponentType::Detection))
            .unwrap();
        let sr = reg.system_readiness();
        assert!(sr.is_ready);
        assert_eq!(sr.total_components, 2);
        assert_eq!(sr.available, 2);
        assert_eq!(sr.unavailable, 0);
    }

    #[test]
    fn test_system_readiness_not_ready() {
        let mut reg = ComponentRegistry::new();
        reg.register(sample_component("sec-1", ComponentType::Security))
            .unwrap();
        reg.update_status(&ComponentId::new("sec-1"), ComponentStatus::Unavailable)
            .unwrap();
        let sr = reg.system_readiness();
        assert!(!sr.is_ready);
        assert_eq!(sr.unavailable, 1);
    }

    #[test]
    fn test_system_readiness_empty_not_ready() {
        let reg = ComponentRegistry::new();
        let sr = reg.system_readiness();
        assert!(!sr.is_ready);
        assert_eq!(sr.total_components, 0);
    }

    #[test]
    fn test_system_readiness_display() {
        let mut reg = ComponentRegistry::new();
        reg.register(sample_component("sec-1", ComponentType::Security))
            .unwrap();
        let sr = reg.system_readiness();
        let display = sr.to_string();
        assert!(display.contains("READY"));
        assert!(display.contains("1/1"));
    }

    #[test]
    fn test_component_metadata() {
        let c = ComponentInfo::new("sec-1", ComponentType::Security, "Security", "1.0.0")
            .with_metadata("region", "us-east-1");
        assert_eq!(c.metadata.get("region").unwrap(), "us-east-1");
    }
}
