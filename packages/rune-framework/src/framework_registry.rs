// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — FrameworkRegistry trait for framework manifest discovery,
// retrieval, and subscription. Ships ten built-in framework manifests.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::backend::{
    FrameworkDomain, Jurisdiction, MappingConfidence, MappingType,
    RequirementPriorityLevel, StoredCrossFrameworkMapping, StoredFrameworkManifest,
    StoredFrameworkRequirement,
};
use crate::error::FrameworkError;

// ── SubscriptionHandle ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubscriptionHandle(pub String);

impl std::fmt::Display for SubscriptionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ── FrameworkQuery ───────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct FrameworkQuery {
    pub name_pattern: Option<String>,
    pub jurisdiction_filter: Option<Jurisdiction>,
    pub domain_filter: Option<FrameworkDomain>,
    pub authority_filter: Option<String>,
    pub effective_at_or_before: Option<i64>,
}

impl FrameworkQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_name_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.name_pattern = Some(pattern.into());
        self
    }

    pub fn with_jurisdiction(mut self, jurisdiction: Jurisdiction) -> Self {
        self.jurisdiction_filter = Some(jurisdiction);
        self
    }

    pub fn with_domain(mut self, domain: FrameworkDomain) -> Self {
        self.domain_filter = Some(domain);
        self
    }

    pub fn with_authority(mut self, authority: impl Into<String>) -> Self {
        self.authority_filter = Some(authority.into());
        self
    }

    pub fn effective_at_or_before(mut self, timestamp: i64) -> Self {
        self.effective_at_or_before = Some(timestamp);
        self
    }

    fn matches(&self, manifest: &StoredFrameworkManifest) -> bool {
        if let Some(ref pattern) = self.name_pattern {
            if !manifest.name.contains(pattern.as_str()) {
                return false;
            }
        }
        if let Some(ref j) = self.jurisdiction_filter {
            if &manifest.jurisdiction != j {
                return false;
            }
        }
        if let Some(ref d) = self.domain_filter {
            if &manifest.domain != d {
                return false;
            }
        }
        if let Some(ref a) = self.authority_filter {
            if &manifest.authority != a.as_str() {
                return false;
            }
        }
        if let Some(ts) = self.effective_at_or_before {
            if manifest.effective_date > ts {
                return false;
            }
        }
        true
    }
}

// ── FrameworkRegistry trait ───────────────────────────────────────────

pub trait FrameworkRegistry {
    fn register_framework(
        &mut self,
        manifest: StoredFrameworkManifest,
    ) -> Result<(), FrameworkError>;

    fn lookup_framework(&self, framework_id: &str) -> Option<&StoredFrameworkManifest>;

    fn list_available_frameworks(&self, query: &FrameworkQuery) -> Vec<&StoredFrameworkManifest>;

    fn list_jurisdictions(&self) -> Vec<&Jurisdiction>;

    fn list_domains(&self) -> Vec<&FrameworkDomain>;

    fn framework_dependency_graph(
        &self,
        framework_id: &str,
    ) -> HashMap<String, Vec<String>>;

    fn subscribe_to_framework_updates(
        &mut self,
        framework_id: &str,
    ) -> Result<SubscriptionHandle, FrameworkError>;

    fn unregister_framework(&mut self, framework_id: &str) -> Result<(), FrameworkError>;

    fn registry_id(&self) -> &str;

    fn is_active(&self) -> bool;
}

// ── InMemoryFrameworkRegistry ────────────────────────────────────────

pub struct InMemoryFrameworkRegistry {
    id: String,
    frameworks: HashMap<String, StoredFrameworkManifest>,
    unregistered: HashMap<String, StoredFrameworkManifest>,
    subscriptions: HashMap<String, Vec<SubscriptionHandle>>,
    next_sub: u64,
}

impl InMemoryFrameworkRegistry {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            frameworks: HashMap::new(),
            unregistered: HashMap::new(),
            subscriptions: HashMap::new(),
            next_sub: 0,
        }
    }

    /// Creates a registry pre-populated with the ten built-in framework manifests.
    pub fn with_builtins(id: impl Into<String>) -> Self {
        let mut reg = Self::new(id);
        for manifest in builtin_framework_manifests() {
            let _ = reg.register_framework(manifest);
        }
        reg
    }
}

impl FrameworkRegistry for InMemoryFrameworkRegistry {
    fn register_framework(
        &mut self,
        manifest: StoredFrameworkManifest,
    ) -> Result<(), FrameworkError> {
        self.frameworks
            .insert(manifest.framework_id.clone(), manifest);
        Ok(())
    }

    fn lookup_framework(&self, framework_id: &str) -> Option<&StoredFrameworkManifest> {
        self.frameworks.get(framework_id)
    }

    fn list_available_frameworks(&self, query: &FrameworkQuery) -> Vec<&StoredFrameworkManifest> {
        self.frameworks
            .values()
            .filter(|m| query.matches(m))
            .collect()
    }

    fn list_jurisdictions(&self) -> Vec<&Jurisdiction> {
        let mut seen = Vec::new();
        for m in self.frameworks.values() {
            if !seen.contains(&&m.jurisdiction) {
                seen.push(&m.jurisdiction);
            }
        }
        seen
    }

    fn list_domains(&self) -> Vec<&FrameworkDomain> {
        let mut seen = Vec::new();
        for m in self.frameworks.values() {
            if !seen.contains(&&m.domain) {
                seen.push(&m.domain);
            }
        }
        seen
    }

    fn framework_dependency_graph(
        &self,
        framework_id: &str,
    ) -> HashMap<String, Vec<String>> {
        let mut graph: HashMap<String, Vec<String>> = HashMap::new();
        if let Some(manifest) = self.frameworks.get(framework_id) {
            let entry = graph.entry(framework_id.to_string()).or_default();
            for mapping_ref in &manifest.mapping_refs {
                entry.push(mapping_ref.clone());
            }
        }
        graph
    }

    fn subscribe_to_framework_updates(
        &mut self,
        framework_id: &str,
    ) -> Result<SubscriptionHandle, FrameworkError> {
        if !self.frameworks.contains_key(framework_id) {
            return Err(FrameworkError::ComponentNotFound {
                component_id: framework_id.to_string(),
            });
        }
        self.next_sub += 1;
        let handle = SubscriptionHandle(format!("sub-{}", self.next_sub));
        self.subscriptions
            .entry(framework_id.to_string())
            .or_default()
            .push(handle.clone());
        Ok(handle)
    }

    fn unregister_framework(&mut self, framework_id: &str) -> Result<(), FrameworkError> {
        let manifest = self.frameworks.remove(framework_id).ok_or_else(|| {
            FrameworkError::ComponentNotFound {
                component_id: framework_id.to_string(),
            }
        })?;
        self.unregistered.insert(framework_id.to_string(), manifest);
        Ok(())
    }

    fn registry_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── ReadOnlyFrameworkRegistry ────────────────────────────────────────

pub struct ReadOnlyFrameworkRegistry<R: FrameworkRegistry> {
    inner: R,
}

impl<R: FrameworkRegistry> ReadOnlyFrameworkRegistry<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }
}

impl<R: FrameworkRegistry> FrameworkRegistry for ReadOnlyFrameworkRegistry<R> {
    fn register_framework(
        &mut self,
        _manifest: StoredFrameworkManifest,
    ) -> Result<(), FrameworkError> {
        Err(FrameworkError::InvalidConfiguration {
            field: "registry".to_string(),
            reason: "read-only registry rejects writes".to_string(),
        })
    }

    fn lookup_framework(&self, framework_id: &str) -> Option<&StoredFrameworkManifest> {
        self.inner.lookup_framework(framework_id)
    }

    fn list_available_frameworks(&self, query: &FrameworkQuery) -> Vec<&StoredFrameworkManifest> {
        self.inner.list_available_frameworks(query)
    }

    fn list_jurisdictions(&self) -> Vec<&Jurisdiction> {
        self.inner.list_jurisdictions()
    }

    fn list_domains(&self) -> Vec<&FrameworkDomain> {
        self.inner.list_domains()
    }

    fn framework_dependency_graph(
        &self,
        framework_id: &str,
    ) -> HashMap<String, Vec<String>> {
        self.inner.framework_dependency_graph(framework_id)
    }

    fn subscribe_to_framework_updates(
        &mut self,
        _framework_id: &str,
    ) -> Result<SubscriptionHandle, FrameworkError> {
        Err(FrameworkError::InvalidConfiguration {
            field: "registry".to_string(),
            reason: "read-only registry rejects subscriptions".to_string(),
        })
    }

    fn unregister_framework(&mut self, _framework_id: &str) -> Result<(), FrameworkError> {
        Err(FrameworkError::InvalidConfiguration {
            field: "registry".to_string(),
            reason: "read-only registry rejects unregister".to_string(),
        })
    }

    fn registry_id(&self) -> &str {
        self.inner.registry_id()
    }

    fn is_active(&self) -> bool {
        self.inner.is_active()
    }
}

// ── CachedFrameworkRegistry ──────────────────────────────────────────

pub struct CachedFrameworkRegistry<R: FrameworkRegistry> {
    inner: R,
    cache: HashMap<String, StoredFrameworkManifest>,
    _max_entries: usize,
    hits: u64,
    misses: u64,
}

impl<R: FrameworkRegistry> CachedFrameworkRegistry<R> {
    pub fn new(inner: R, max_entries: usize) -> Self {
        Self {
            inner,
            cache: HashMap::new(),
            _max_entries: max_entries,
            hits: 0,
            misses: 0,
        }
    }

    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            return 0.0;
        }
        self.hits as f64 / total as f64
    }

    pub fn invalidate(&mut self, framework_id: &str) {
        self.cache.remove(framework_id);
    }

    pub fn invalidate_all(&mut self) {
        self.cache.clear();
    }

    pub fn cached_lookup(&mut self, framework_id: &str) -> Option<&StoredFrameworkManifest> {
        if self.cache.contains_key(framework_id) {
            self.hits += 1;
            return self.cache.get(framework_id);
        }
        self.misses += 1;
        if let Some(manifest) = self.inner.lookup_framework(framework_id) {
            self.cache
                .insert(framework_id.to_string(), manifest.clone());
            return self.cache.get(framework_id);
        }
        None
    }
}

impl<R: FrameworkRegistry> FrameworkRegistry for CachedFrameworkRegistry<R> {
    fn register_framework(
        &mut self,
        manifest: StoredFrameworkManifest,
    ) -> Result<(), FrameworkError> {
        let id = manifest.framework_id.clone();
        let result = self.inner.register_framework(manifest);
        if result.is_ok() {
            self.invalidate(&id);
        }
        result
    }

    fn lookup_framework(&self, framework_id: &str) -> Option<&StoredFrameworkManifest> {
        if let Some(cached) = self.cache.get(framework_id) {
            return Some(cached);
        }
        self.inner.lookup_framework(framework_id)
    }

    fn list_available_frameworks(&self, query: &FrameworkQuery) -> Vec<&StoredFrameworkManifest> {
        self.inner.list_available_frameworks(query)
    }

    fn list_jurisdictions(&self) -> Vec<&Jurisdiction> {
        self.inner.list_jurisdictions()
    }

    fn list_domains(&self) -> Vec<&FrameworkDomain> {
        self.inner.list_domains()
    }

    fn framework_dependency_graph(
        &self,
        framework_id: &str,
    ) -> HashMap<String, Vec<String>> {
        self.inner.framework_dependency_graph(framework_id)
    }

    fn subscribe_to_framework_updates(
        &mut self,
        framework_id: &str,
    ) -> Result<SubscriptionHandle, FrameworkError> {
        self.inner.subscribe_to_framework_updates(framework_id)
    }

    fn unregister_framework(&mut self, framework_id: &str) -> Result<(), FrameworkError> {
        let result = self.inner.unregister_framework(framework_id);
        if result.is_ok() {
            self.invalidate(framework_id);
        }
        result
    }

    fn registry_id(&self) -> &str {
        self.inner.registry_id()
    }

    fn is_active(&self) -> bool {
        self.inner.is_active()
    }
}

// ── NullFrameworkRegistry ────────────────────────────────────────────

pub struct NullFrameworkRegistry;

impl NullFrameworkRegistry {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NullFrameworkRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameworkRegistry for NullFrameworkRegistry {
    fn register_framework(&mut self, _: StoredFrameworkManifest) -> Result<(), FrameworkError> {
        Ok(())
    }
    fn lookup_framework(&self, _: &str) -> Option<&StoredFrameworkManifest> {
        None
    }
    fn list_available_frameworks(&self, _: &FrameworkQuery) -> Vec<&StoredFrameworkManifest> {
        vec![]
    }
    fn list_jurisdictions(&self) -> Vec<&Jurisdiction> {
        vec![]
    }
    fn list_domains(&self) -> Vec<&FrameworkDomain> {
        vec![]
    }
    fn framework_dependency_graph(&self, _: &str) -> HashMap<String, Vec<String>> {
        HashMap::new()
    }
    fn subscribe_to_framework_updates(
        &mut self,
        _: &str,
    ) -> Result<SubscriptionHandle, FrameworkError> {
        Ok(SubscriptionHandle("null".to_string()))
    }
    fn unregister_framework(&mut self, _: &str) -> Result<(), FrameworkError> {
        Ok(())
    }
    fn registry_id(&self) -> &str {
        "null"
    }
    fn is_active(&self) -> bool {
        false
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Built-in framework manifests
// ═══════════════════════════════════════════════════════════════════════

pub fn builtin_framework_manifests() -> Vec<StoredFrameworkManifest> {
    vec![
        cjis_v6_0_manifest(),
        gdpr_manifest(),
        hipaa_manifest(),
        pci_dss_v4_manifest(),
        fedramp_moderate_manifest(),
        fedramp_high_manifest(),
        nist_sp_800_53_manifest(),
        nist_ai_rmf_manifest(),
        eu_ai_act_manifest(),
        soc2_manifest(),
    ]
}

fn cjis_v6_0_manifest() -> StoredFrameworkManifest {
    StoredFrameworkManifest {
        framework_id: "cjis-v6.0".to_string(),
        name: "CJIS Security Policy".to_string(),
        version: "6.0.0".to_string(),
        jurisdiction: Jurisdiction::UnitedStates,
        domain: FrameworkDomain::CriminalJustice,
        description: "FBI Criminal Justice Information Services Security Policy v6.0".to_string(),
        authority: "FBI CJIS Division".to_string(),
        policy_area_count: 20,
        requirement_refs: vec![
            "cjis-5.1".to_string(),
            "cjis-5.4".to_string(),
            "cjis-5.5".to_string(),
            "cjis-5.6".to_string(),
            "cjis-5.10".to_string(),
        ],
        mapping_refs: vec!["cjis-to-nist-800-53".to_string()],
        published_at: 1735257600,
        effective_date: 1735257600,
        sunset_date: None,
        metadata: {
            let mut m = HashMap::new();
            m.insert("enforcement_deadline".to_string(), "2027-10-01".to_string());
            m
        },
    }
}

fn gdpr_manifest() -> StoredFrameworkManifest {
    StoredFrameworkManifest {
        framework_id: "gdpr".to_string(),
        name: "General Data Protection Regulation".to_string(),
        version: "2016/679".to_string(),
        jurisdiction: Jurisdiction::EuropeanUnion,
        domain: FrameworkDomain::GeneralPrivacy,
        description: "EU General Data Protection Regulation".to_string(),
        authority: "European Parliament".to_string(),
        policy_area_count: 11,
        requirement_refs: vec![
            "gdpr-art-5".to_string(),
            "gdpr-art-6".to_string(),
            "gdpr-art-17".to_string(),
            "gdpr-art-25".to_string(),
            "gdpr-art-32".to_string(),
        ],
        mapping_refs: vec!["gdpr-to-iso-27001".to_string()],
        published_at: 1462060800,
        effective_date: 1527811200,
        sunset_date: None,
        metadata: HashMap::new(),
    }
}

fn hipaa_manifest() -> StoredFrameworkManifest {
    StoredFrameworkManifest {
        framework_id: "hipaa".to_string(),
        name: "Health Insurance Portability and Accountability Act".to_string(),
        version: "45-CFR-164".to_string(),
        jurisdiction: Jurisdiction::UnitedStates,
        domain: FrameworkDomain::Healthcare,
        description: "HIPAA Security Rule and Privacy Rule".to_string(),
        authority: "HHS Office for Civil Rights".to_string(),
        policy_area_count: 3,
        requirement_refs: vec![
            "hipaa-164.312-a".to_string(),
            "hipaa-164.312-b".to_string(),
            "hipaa-164.312-c".to_string(),
            "hipaa-164.312-d".to_string(),
            "hipaa-164.312-e".to_string(),
        ],
        mapping_refs: vec!["hipaa-to-nist-800-66".to_string()],
        published_at: 934848000,
        effective_date: 1050451200,
        sunset_date: None,
        metadata: HashMap::new(),
    }
}

fn pci_dss_v4_manifest() -> StoredFrameworkManifest {
    StoredFrameworkManifest {
        framework_id: "pci-dss-v4.0".to_string(),
        name: "Payment Card Industry Data Security Standard".to_string(),
        version: "4.0.0".to_string(),
        jurisdiction: Jurisdiction::International,
        domain: FrameworkDomain::PaymentCard,
        description: "PCI DSS v4.0 requirements for cardholder data protection".to_string(),
        authority: "PCI Security Standards Council".to_string(),
        policy_area_count: 12,
        requirement_refs: vec![
            "pci-req-1".to_string(),
            "pci-req-3".to_string(),
            "pci-req-8".to_string(),
            "pci-req-10".to_string(),
        ],
        mapping_refs: vec!["pci-to-nist-800-53".to_string()],
        published_at: 1648512000,
        effective_date: 1711929600,
        sunset_date: None,
        metadata: HashMap::new(),
    }
}

fn fedramp_moderate_manifest() -> StoredFrameworkManifest {
    StoredFrameworkManifest {
        framework_id: "fedramp-moderate".to_string(),
        name: "FedRAMP Moderate Baseline".to_string(),
        version: "rev5".to_string(),
        jurisdiction: Jurisdiction::UnitedStates,
        domain: FrameworkDomain::FederalGovernment,
        description: "FedRAMP Moderate baseline for cloud services".to_string(),
        authority: "GSA FedRAMP PMO".to_string(),
        policy_area_count: 17,
        requirement_refs: vec![
            "fedramp-mod-ac".to_string(),
            "fedramp-mod-ia".to_string(),
            "fedramp-mod-sc".to_string(),
        ],
        mapping_refs: vec!["fedramp-to-nist-800-53".to_string()],
        published_at: 1672531200,
        effective_date: 1672531200,
        sunset_date: None,
        metadata: HashMap::new(),
    }
}

fn fedramp_high_manifest() -> StoredFrameworkManifest {
    StoredFrameworkManifest {
        framework_id: "fedramp-high".to_string(),
        name: "FedRAMP High Baseline".to_string(),
        version: "rev5".to_string(),
        jurisdiction: Jurisdiction::UnitedStates,
        domain: FrameworkDomain::FederalGovernment,
        description: "FedRAMP High baseline for cloud services".to_string(),
        authority: "GSA FedRAMP PMO".to_string(),
        policy_area_count: 17,
        requirement_refs: vec![
            "fedramp-high-ac".to_string(),
            "fedramp-high-ia".to_string(),
            "fedramp-high-sc".to_string(),
            "fedramp-high-pe".to_string(),
        ],
        mapping_refs: vec!["fedramp-to-nist-800-53".to_string()],
        published_at: 1672531200,
        effective_date: 1672531200,
        sunset_date: None,
        metadata: HashMap::new(),
    }
}

fn nist_sp_800_53_manifest() -> StoredFrameworkManifest {
    StoredFrameworkManifest {
        framework_id: "nist-sp-800-53-r5".to_string(),
        name: "NIST SP 800-53 Rev. 5".to_string(),
        version: "5.0.0".to_string(),
        jurisdiction: Jurisdiction::UnitedStates,
        domain: FrameworkDomain::FederalGovernment,
        description: "Security and Privacy Controls for Information Systems".to_string(),
        authority: "NIST".to_string(),
        policy_area_count: 20,
        requirement_refs: vec![
            "nist-ac-1".to_string(),
            "nist-ia-2".to_string(),
            "nist-sc-7".to_string(),
            "nist-au-2".to_string(),
        ],
        mapping_refs: vec![],
        published_at: 1600300800,
        effective_date: 1600300800,
        sunset_date: None,
        metadata: HashMap::new(),
    }
}

fn nist_ai_rmf_manifest() -> StoredFrameworkManifest {
    StoredFrameworkManifest {
        framework_id: "nist-ai-rmf-1.0".to_string(),
        name: "NIST AI Risk Management Framework".to_string(),
        version: "1.0.0".to_string(),
        jurisdiction: Jurisdiction::UnitedStates,
        domain: FrameworkDomain::ArtificialIntelligence,
        description: "AI Risk Management Framework for trustworthy AI".to_string(),
        authority: "NIST".to_string(),
        policy_area_count: 4,
        requirement_refs: vec![
            "ai-rmf-govern".to_string(),
            "ai-rmf-map".to_string(),
            "ai-rmf-measure".to_string(),
            "ai-rmf-manage".to_string(),
        ],
        mapping_refs: vec![],
        published_at: 1674518400,
        effective_date: 1674518400,
        sunset_date: None,
        metadata: HashMap::new(),
    }
}

fn eu_ai_act_manifest() -> StoredFrameworkManifest {
    StoredFrameworkManifest {
        framework_id: "eu-ai-act-2024".to_string(),
        name: "EU Artificial Intelligence Act".to_string(),
        version: "2024/1689".to_string(),
        jurisdiction: Jurisdiction::EuropeanUnion,
        domain: FrameworkDomain::ArtificialIntelligence,
        description: "Regulation laying down harmonised rules on artificial intelligence".to_string(),
        authority: "European Parliament".to_string(),
        policy_area_count: 13,
        requirement_refs: vec![
            "eu-ai-art-6".to_string(),
            "eu-ai-art-9".to_string(),
            "eu-ai-art-13".to_string(),
            "eu-ai-art-14".to_string(),
        ],
        mapping_refs: vec![],
        published_at: 1720828800,
        effective_date: 1722902400,
        sunset_date: None,
        metadata: HashMap::new(),
    }
}

fn soc2_manifest() -> StoredFrameworkManifest {
    StoredFrameworkManifest {
        framework_id: "soc2-tsc-2017".to_string(),
        name: "SOC 2 Trust Services Criteria".to_string(),
        version: "2017".to_string(),
        jurisdiction: Jurisdiction::International,
        domain: FrameworkDomain::CloudServices,
        description: "AICPA Trust Services Criteria for SOC 2 Type II".to_string(),
        authority: "AICPA".to_string(),
        policy_area_count: 5,
        requirement_refs: vec![
            "soc2-cc".to_string(),
            "soc2-availability".to_string(),
            "soc2-processing-integrity".to_string(),
            "soc2-confidentiality".to_string(),
            "soc2-privacy".to_string(),
        ],
        mapping_refs: vec![],
        published_at: 1483228800,
        effective_date: 1483228800,
        sunset_date: None,
        metadata: HashMap::new(),
    }
}

// ── Built-in requirements (representative subset) ────────────────────

pub fn builtin_cjis_requirements() -> Vec<StoredFrameworkRequirement> {
    vec![
        StoredFrameworkRequirement {
            requirement_id: "cjis-5.6.2.1".to_string(),
            framework_id: "cjis-v6.0".to_string(),
            requirement_identifier: "CJIS-5.6.2.1".to_string(),
            title: "Advanced Authentication".to_string(),
            description: "Multi-factor authentication for CJI access".to_string(),
            policy_area: "Identification and Authentication".to_string(),
            priority_level: RequirementPriorityLevel::Sanctionable,
            referenced_library: "rune-identity".to_string(),
            referenced_capability: "FactorType::Possession".to_string(),
            evaluation_context_hint: HashMap::new(),
        },
        StoredFrameworkRequirement {
            requirement_id: "cjis-5.4.1".to_string(),
            framework_id: "cjis-v6.0".to_string(),
            requirement_identifier: "CJIS-5.4.1".to_string(),
            title: "Auditable Events".to_string(),
            description: "Audit trail for all CJI access and modifications".to_string(),
            policy_area: "Auditing and Accountability".to_string(),
            priority_level: RequirementPriorityLevel::Sanctionable,
            referenced_library: "rune-audit-ext".to_string(),
            referenced_capability: "AuditBackend::store_event".to_string(),
            evaluation_context_hint: HashMap::new(),
        },
        StoredFrameworkRequirement {
            requirement_id: "cjis-5.10.1".to_string(),
            framework_id: "cjis-v6.0".to_string(),
            requirement_identifier: "CJIS-5.10.1".to_string(),
            title: "Encryption in Transit".to_string(),
            description: "Minimum 128-bit encryption for CJI in transit".to_string(),
            policy_area: "Systems and Communications Protection".to_string(),
            priority_level: RequirementPriorityLevel::Sanctionable,
            referenced_library: "rune-security".to_string(),
            referenced_capability: "encryption_in_transit".to_string(),
            evaluation_context_hint: HashMap::new(),
        },
    ]
}

// ── Built-in cross-framework mappings ────────────────────────────────

pub fn builtin_cross_framework_mappings() -> Vec<StoredCrossFrameworkMapping> {
    vec![
        // CJIS → NIST SP 800-53
        StoredCrossFrameworkMapping {
            mapping_id: "cjis-5.6-to-nist-ia-2".to_string(),
            source_requirement_id: "cjis-5.6.2.1".to_string(),
            target_requirement_id: "nist-ia-2".to_string(),
            mapping_type: MappingType::Equivalent,
            confidence: MappingConfidence::Authoritative,
            justification: "CJIS v6.0 Section 5.6 aligns with NIST SP 800-53 IA-2".to_string(),
            mapped_by: "rune-framework-builtin".to_string(),
            mapped_at: 0,
        },
        StoredCrossFrameworkMapping {
            mapping_id: "cjis-5.4-to-nist-au-2".to_string(),
            source_requirement_id: "cjis-5.4.1".to_string(),
            target_requirement_id: "nist-au-2".to_string(),
            mapping_type: MappingType::Subset,
            confidence: MappingConfidence::HighConfidence,
            justification: "CJIS audit requirements are a subset of NIST AU-2".to_string(),
            mapped_by: "rune-framework-builtin".to_string(),
            mapped_at: 0,
        },
        // GDPR → ISO 27001
        StoredCrossFrameworkMapping {
            mapping_id: "gdpr-art-32-to-iso-27001-a14".to_string(),
            source_requirement_id: "gdpr-art-32".to_string(),
            target_requirement_id: "iso-27001-a14".to_string(),
            mapping_type: MappingType::Related,
            confidence: MappingConfidence::HighConfidence,
            justification: "GDPR Art. 32 security of processing relates to ISO 27001 A.14".to_string(),
            mapped_by: "rune-framework-builtin".to_string(),
            mapped_at: 0,
        },
        // PCI DSS → NIST SP 800-53
        StoredCrossFrameworkMapping {
            mapping_id: "pci-req-8-to-nist-ia-2".to_string(),
            source_requirement_id: "pci-req-8".to_string(),
            target_requirement_id: "nist-ia-2".to_string(),
            mapping_type: MappingType::Related,
            confidence: MappingConfidence::HighConfidence,
            justification: "PCI DSS Req 8 authentication maps to NIST IA-2".to_string(),
            mapped_by: "rune-framework-builtin".to_string(),
            mapped_at: 0,
        },
    ]
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_lookup() {
        let mut reg = InMemoryFrameworkRegistry::new("test");
        reg.register_framework(cjis_v6_0_manifest()).unwrap();
        assert!(reg.lookup_framework("cjis-v6.0").is_some());
        assert!(reg.lookup_framework("nonexistent").is_none());
    }

    #[test]
    fn test_with_builtins_has_ten_frameworks() {
        let reg = InMemoryFrameworkRegistry::with_builtins("test");
        let all = reg.list_available_frameworks(&FrameworkQuery::new());
        assert_eq!(all.len(), 10);
    }

    #[test]
    fn test_query_by_jurisdiction() {
        let reg = InMemoryFrameworkRegistry::with_builtins("test");
        let us = reg.list_available_frameworks(
            &FrameworkQuery::new().with_jurisdiction(Jurisdiction::UnitedStates),
        );
        // CJIS, HIPAA, FedRAMP Moderate, FedRAMP High, NIST 800-53, NIST AI RMF
        assert_eq!(us.len(), 6);
    }

    #[test]
    fn test_query_by_domain() {
        let reg = InMemoryFrameworkRegistry::with_builtins("test");
        let ai = reg.list_available_frameworks(
            &FrameworkQuery::new().with_domain(FrameworkDomain::ArtificialIntelligence),
        );
        // NIST AI RMF, EU AI Act
        assert_eq!(ai.len(), 2);
    }

    #[test]
    fn test_unregister_soft_deletes() {
        let mut reg = InMemoryFrameworkRegistry::new("test");
        reg.register_framework(cjis_v6_0_manifest()).unwrap();
        reg.unregister_framework("cjis-v6.0").unwrap();
        assert!(reg.lookup_framework("cjis-v6.0").is_none());
        assert!(reg.unregister_framework("cjis-v6.0").is_err());
    }

    #[test]
    fn test_subscribe_returns_handle() {
        let mut reg = InMemoryFrameworkRegistry::new("test");
        reg.register_framework(cjis_v6_0_manifest()).unwrap();
        let handle = reg.subscribe_to_framework_updates("cjis-v6.0").unwrap();
        assert!(handle.0.starts_with("sub-"));
    }

    #[test]
    fn test_subscribe_to_nonexistent_fails() {
        let mut reg = InMemoryFrameworkRegistry::new("test");
        assert!(reg.subscribe_to_framework_updates("nonexistent").is_err());
    }

    #[test]
    fn test_read_only_registry_rejects_writes() {
        let inner = InMemoryFrameworkRegistry::with_builtins("test");
        let mut ro = ReadOnlyFrameworkRegistry::new(inner);
        assert!(ro.register_framework(cjis_v6_0_manifest()).is_err());
        assert!(ro.unregister_framework("cjis-v6.0").is_err());
        assert!(ro.subscribe_to_framework_updates("cjis-v6.0").is_err());
        // reads work
        assert!(ro.lookup_framework("cjis-v6.0").is_some());
    }

    #[test]
    fn test_cached_registry_hit_rate() {
        let inner = InMemoryFrameworkRegistry::with_builtins("test");
        let mut cached = CachedFrameworkRegistry::new(inner, 100);
        assert_eq!(cached.hit_rate(), 0.0);
        // first lookup is a miss
        cached.cached_lookup("cjis-v6.0");
        assert_eq!(cached.misses, 1);
        // second is a hit
        cached.cached_lookup("cjis-v6.0");
        assert_eq!(cached.hits, 1);
        assert!(cached.hit_rate() > 0.0);
    }

    #[test]
    fn test_cached_registry_invalidate() {
        let inner = InMemoryFrameworkRegistry::with_builtins("test");
        let mut cached = CachedFrameworkRegistry::new(inner, 100);
        cached.cached_lookup("cjis-v6.0");
        cached.invalidate("cjis-v6.0");
        // after invalidation, next lookup is a miss again
        cached.cached_lookup("cjis-v6.0");
        assert_eq!(cached.misses, 2);
    }

    #[test]
    fn test_null_registry() {
        let mut reg = NullFrameworkRegistry::new();
        assert!(reg.lookup_framework("any").is_none());
        assert!(!reg.is_active());
        assert_eq!(reg.registry_id(), "null");
        assert!(reg.register_framework(cjis_v6_0_manifest()).is_ok());
    }

    #[test]
    fn test_list_jurisdictions_and_domains() {
        let reg = InMemoryFrameworkRegistry::with_builtins("test");
        let jurisdictions = reg.list_jurisdictions();
        assert!(jurisdictions.len() >= 2); // at least US and EU
        let domains = reg.list_domains();
        assert!(domains.len() >= 4);
    }

    #[test]
    fn test_builtin_requirements() {
        let reqs = builtin_cjis_requirements();
        assert_eq!(reqs.len(), 3);
        assert!(reqs.iter().all(|r| r.framework_id == "cjis-v6.0"));
    }

    #[test]
    fn test_builtin_cross_framework_mappings() {
        let mappings = builtin_cross_framework_mappings();
        assert_eq!(mappings.len(), 4);
        assert!(mappings.iter().any(|m| m.confidence == MappingConfidence::Authoritative));
    }
}
