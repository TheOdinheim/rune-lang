# RUNE Build Log 18

> Previous file: [BUILD_LOG_17.md](BUILD_LOG_17.md)

---

## rune-safety Layer 3

**Date**: 2026-04-21
**Test count**: 151 → 238 (+87 tests, zero failures)
**Commit**: `6d80b16`

**Clippy**: Zero rune-safety-specific warnings (pre-existing L1/L2 warnings untouched)

### What Changed

Layer 3 adds the operational AI safety infrastructure layer: pluggable backend storage for safety constraints, envelopes, cases, boundary violation records, and shutdown records; safety envelope monitoring with numeric threshold proximity detection; structured safety case construction with completeness assessment; emergency shutdown control with mandatory reauthorization; five export formats (JSON, GSN XML, Markdown safety case reports, Bow-tie analysis, NIST-aligned incident reports); lifecycle event streaming with system/severity/event-type filtering; and operational safety metrics (envelope compliance rate, mean time to safe state, violation frequency, safety case coverage).

### New Modules (7)

| Module | Lines | Tests | Purpose |
|--------|-------|-------|---------|
| `backend.rs` | ~732 | 15 | SafetyBackend trait + InMemorySafetyBackend |
| `safety_envelope.rs` | ~590 | 12 | SafetyEnvelopeMonitor trait + 3 implementations |
| `safety_case_builder.rs` | ~461 | 11 | SafetyCaseBuilder trait + InMemorySafetyCaseBuilder |
| `emergency_shutdown.rs` | ~459 | 11 | EmergencyShutdownController trait + AuditedEmergencyShutdownController |
| `safety_export.rs` | ~668 | 9 | SafetyExporter trait + 5 format implementations |
| `safety_stream.rs` | ~380 | 10 | SafetyEventSubscriber trait + registry + filtering |
| `safety_metrics.rs` | ~403 | 11 | SafetyMetricsCollector trait + InMemorySafetyMetricsCollector |

### Trait Contracts

- **SafetyBackend**: 18 methods — store/retrieve/delete constraints, list by category, constraint_count, store/retrieve envelopes, list by system, store/retrieve safety cases, list by system, store/retrieve boundary violation records, list by envelope, store/retrieve shutdown records, list by system, flush/backend_info. InMemorySafetyBackend reference implementation. ConstraintCategory 7-variant (OperationalBoundary/BehavioralLimit/ResourceLimit/TemporalLimit/InteractionLimit/DataBoundary/Other), ConstraintSeverityLevel 4-variant (Advisory/Mandatory/Critical/Absolute), StoredEnvelopeStatus 3-variant (Active/Suspended/Retired), SafetyCaseMethodology 5-variant (Gsn/Cae/Amlas/NistAiRmf/Custom), SafetyCaseRecordStatus 5-variant (Draft/UnderReview/Accepted/Challenged/Withdrawn), ShutdownType 4-variant (EmergencyImmediate/GracefulDegradation/ScheduledMaintenance/ManualOverride). StoredSafetyEnvelope with constraint_refs/safe_state_description/degraded_operation_available. StoredShutdownRecord with reauthorization_required/reauthorized_by/reauthorized_at.
- **SafetyEnvelopeMonitor**: 7 methods — check_envelope/register_constraint/remove_constraint/list_active_constraints/recommend_response/monitor_id/is_active. EnvelopeStatus 5-variant (WithinEnvelope/ApproachingBoundary/BoundaryViolated/EnvelopeSuspended/Unknown). RecommendedSafetyResponse 5-variant (ContinueOperation/IncreasedMonitoring/DegradedOperation/EmergencyShutdown/EscalateToHuman). InMemorySafetyEnvelopeMonitor (key-value matching), ThresholdBasedSafetyEnvelopeMonitor (numeric threshold comparison with configurable proximity percentage for ApproachingBoundary detection), NullSafetyEnvelopeMonitor.
- **SafetyCaseBuilder**: 8 methods — create_case/add_claim/add_argument/add_evidence_ref/assess_completeness/finalize_case/builder_id/is_active. SafetyClaim with claim_type (TopLevel/SubClaim/Assumption/Justification/Context) and status (Unsupported/PartiallySupported/FullySupported/Challenged). SafetyArgument with argument_type (DirectEvidence/InferentialLink/Decomposition/Concretion). CompletenessAssessment with unsupported_claims/uncovered_hazards. InMemorySafetyCaseBuilder (rejects modifications after finalize), NullSafetyCaseBuilder.
- **EmergencyShutdownController**: 7 methods — initiate_shutdown/check_shutdown_status/request_reauthorization/list_active_shutdowns/list_shutdown_history_for_system/controller_id/is_active. ShutdownHandle opaque string newtype. ShutdownStatus 5-variant (Initiated/InProgress/Completed/Failed/Reauthorized). InMemoryEmergencyShutdownController (immediate completion for testing), AuditedEmergencyShutdownController<C> (composable wrapper ensuring every shutdown/reauthorization produces an audit record), NullEmergencyShutdownController.
- **SafetyExporter**: 6 methods — export_safety_case/export_envelope/export_violation_report/export_batch/format_name/content_type. JsonSafetyExporter (full JSON with safety case/envelope/violation structure), GsnXmlExporter (Goal Structuring Notation XML with goal/strategy/solution elements — structure only, not graphical rendering), SafetyCaseReportExporter (Markdown-formatted human review report), BowTieExporter (hazard/threats/barriers/consequences structure for process safety risk analysis), IncidentReportExporter (NIST IR-aligned incident report with compatible field names for security/safety incident pipeline convergence). All preserve evidence_refs and constraint_refs.
- **SafetyEventSubscriber**: 3 methods — on_safety_event/subscriber_id/is_active. SafetyEventSubscriberRegistry with register/notify/notify_batch/active_count/remove_inactive. SafetyEventCollector reference implementation. FilteredSafetyEventSubscriber<S> with system_id/event_type/severity filters using let-chains. SafetyLifecycleEventType 20-variant enum.
- **SafetyMetricsCollector**: 7 methods — compute_envelope_compliance_rate/compute_mean_time_to_safe_state/compute_violation_frequency/list_most_violated_constraints/compute_safety_case_coverage/collector_id/is_active. SafetyMetricSnapshot with all computed values as String for Eq derivation. InMemorySafetyMetricsCollector (computes from stored violation/shutdown records), NullSafetyMetricsCollector.

### Modified Files

- **audit.rs**: 22 new SafetyEventType L3 variants with struct fields. Display impl delegates L3 variants to type_name(). Added type_name()/kind() methods covering all 48 variants (26 L1/L2 + 22 L3). Classification methods: is_backend_event/is_envelope_event/is_case_event/is_shutdown_event/is_violation_event/is_export_event/is_metrics_event. Test constructs every L3 variant and asserts non-empty Display and kind() output.
- **error.rs**: 3 new SafetyError variants: SerializationFailed(String), EnvelopeNotFound(String), ShutdownNotFound(String). Display impl updated. Test updated to cover all 19 variants.
- **lib.rs**: 7 new module declarations under Layer 3 section. Layer 3 re-exports grouped under `// ── Layer 3 re-exports ──` comment.

### Naming Collision Resolutions

| L1/L2 type | L3 type | Rationale |
|---|---|---|
| `safety_case.rs` (L1 module: SafetyCase, SafetyCaseId, SafetyGoal, etc.) | `safety_case_builder.rs` (L3 module: SafetyCaseBuilder, SafetyClaim, SafetyArgument) | L1 defines the safety case data model; L3 defines the construction trait. `_builder` suffix avoids module name collision |
| `ConstraintSeverity` (L1 enum: Advisory/Caution/Warning/Critical/Catastrophic) | `ConstraintSeverityLevel` (L3 enum: Advisory/Mandatory/Critical/Absolute) | L1 measures impact severity; L3 measures enforcement level. Different semantic axes |
| `SafetyMetricsComputed` (L2 audit variant) | `OperationalSafetyMetricsComputed` (L3 audit variant) | `Operational` prefix distinguishes L3 backend-computed metrics from L2 dashboard metrics |
| `SafetyCaseUpdated` (L1 audit variant) | `StoredSafetyCaseCreated/Finalized/Challenged` (L3 audit variants) | `Stored` prefix distinguishes backend-level case operations from L1 data model updates |
| `BoundaryViolationDetected` (L2 audit variant) | `BoundaryViolationRecorded` (L3 audit variant) | L2 detects; L3 records to backend. `Recorded` distinguishes persistence from detection |

### Design Decisions

- **rune-safety distinct from rune-detection**: rune-detection asks "is this anomalous?" and produces detection findings/alerts. rune-safety asks "given a boundary violation, what is the safe response?" The distinction is detection signal vs safety response policy. A rune-detection alert might trigger a rune-safety envelope check, but the envelope evaluation and response recommendation live in rune-safety.
- **rune-safety distinct from rune-shield**: rune-shield handles inference-layer protection (prompt injection, data exfiltration, adversarial inputs) — the model boundary. rune-safety handles operational system safety (envelopes, cases, shutdowns) — the system boundary. A shield verdict might indicate a safety envelope violation, but the envelope monitoring and shutdown mechanism live in rune-safety.
- **rune-safety distinct from rune-agents**: rune-agents governs agent behavior and autonomy boundaries. rune-safety provides safety primitives that exist independently of any agent runtime. Safety constraints and envelopes apply to any system — agent, pipeline, service — not just agents. A rune-agents autonomy boundary might reference a rune-safety constraint, but the constraint definition and evaluation belong to rune-safety.
- **Safety cases do not include GSN/CAE rendering**: GSN XML structure (goal/strategy/solution elements) is exported, but graphical rendering (node layout, arrow routing, color coding) belongs in adapter crates that depend on visualization libraries. The core library defines the structured argument, not its visual presentation.
- **EmergencyShutdownController requires explicit reauthorization**: Irreversibility is a safety property. A compromised system must not be able to restart itself after an emergency shutdown. The reauthorization_required flag and request_reauthorization method enforce that a human (or authorized external system) must explicitly re-enable the system. This matches IEC 61508 requirements for safety function independence.
- **ThresholdBasedSafetyEnvelopeMonitor first-class**: Numeric threshold comparison is the dominant envelope monitoring pattern in process safety (temperature > max, latency > SLA, error_rate > threshold). Having a reference implementation that handles numeric comparison with proximity detection (ApproachingBoundary) directly, rather than requiring every customer to implement it, reduces integration burden for the most common use case.
- **AuditedEmergencyShutdownController composable wrapper**: Wraps any EmergencyShutdownController and ensures every initiate/reauthorize operation produces an audit record. Follows the composable wrapper pattern now established across seven libraries (SlaEnforcing in rune-security, LegalHoldAware in rune-document, DepthLimited in rune-provenance/rune-explainability, FreshnessAware in rune-framework, ContinuityEnforcing in rune-provenance, ExpiryAware in rune-permissions).
- **Safety metrics use String for all computed values**: envelope_compliance_rate, mean_time_to_safe_state, violation_count, safety_case_coverage are all String fields. This enables Eq derivation for deterministic testing, matching the pattern established across the pass (rune-security PostureWeights, rune-monitoring MetricPoint, rune-detection TimeSeriesPoint, etc.).
- **rune-safety does not claim to solve the alignment problem**: Honest scope framing. rune-safety provides operational safety infrastructure — constraints, envelopes, cases, shutdowns, metrics. It does not guarantee safe AI behavior, solve alignment, replace human oversight, or provide interpretability (that is rune-explainability). The module names and trait contracts reflect engineering primitives, not theoretical guarantees.

### Four-Pillar Alignment

| Pillar | Alignment |
|--------|-----------|
| **Transparency** | All backend operations emit structured audit events. Safety cases are exportable in standards-aligned formats (GSN XML, Markdown reports, Bow-tie analysis). Lifecycle event streaming enables real-time observability of envelope monitoring, violation detection, and shutdown operations. Safety metrics provide quantified visibility into operational safety posture. |
| **Accountability** | Every StoredShutdownRecord carries initiated_by/reauthorized_by actor metadata. AuditedEmergencyShutdownController ensures every shutdown/reauthorization produces an auditable record. Safety case completeness assessment identifies unsupported claims and uncovered hazards. Evidence refs link safety arguments to external attestation artifacts. |
| **Fairness** | Safety envelopes define uniform operational boundaries applied consistently across system instances. ConstraintSeverityLevel (Advisory/Mandatory/Critical/Absolute) provides graduated enforcement that distinguishes suggestions from non-negotiable requirements. CompletenessAssessment prevents safety cases from being finalized with unsupported claims. |
| **Safety** | Emergency shutdown with mandatory reauthorization prevents compromised systems from self-restarting. ThresholdBasedSafetyEnvelopeMonitor detects ApproachingBoundary before violation occurs. SafetyCaseBuilder structured argumentation requires evidence for every claim. Five-level SafetyCaseRecordStatus (Draft/UnderReview/Accepted/Challenged/Withdrawn) enforces review lifecycle. |

### Integration Points

- **rune-detection**: Envelope violations may be triggered by detection findings; rune-safety defines the response policy (degrade/shutdown/escalate) while rune-detection defines the detection signal (anomaly/alert)
- **rune-shield**: Shield verdicts may indicate safety envelope violations; rune-safety monitors the system-level envelope while rune-shield protects the inference boundary
- **rune-framework**: Framework requirements reference rune-safety capabilities via opaque strings (e.g. referenced_library: "rune-safety", referenced_capability: "SafetyEnvelopeMonitor") for CJIS/IEC 61508/ISO 26262 compliance
- **rune-agents**: Agent autonomy boundaries may reference safety constraints; rune-safety provides the constraint definitions and envelope monitoring that agent governance can invoke
- **rune-explainability**: When rune-safety triggers an emergency shutdown, rune-explainability can explain why the shutdown was triggered via reasoning traces and feature attributions; the shutdown mechanism lives in rune-safety, the explanation in rune-explainability

---

## rune-agents Layer 3

**Date**: 2026-04-20
**Test count**: 153 → 239 (+86 tests, zero failures)
**Commit**: (pending)

**Clippy**: Zero rune-agents-specific warnings (pre-existing L1/L2 warnings untouched)

### What Changed

Layer 3 adds the agent governance infrastructure layer: pluggable backend storage for governance profiles, autonomy configurations, tool policies, delegation chain records, and governance snapshots; autonomy level evaluation with escalation detection and EU AI Act Article 14 compliance (AlwaysEscalateAutonomyController); tool-use governance with per-agent policies, invocation limits, and rate limiting; delegation chain governance with depth limit enforcement; five export formats (JSON, agent card, human oversight report, NIST AI RMF autonomy assessment, delegation chain report); lifecycle event streaming with agent_id/event_type/severity filtering; and agent governance metrics (autonomy escalation rate, tool denial rate, delegation depth average, human oversight frequency).

### New Modules (7)

| Module | Lines | Tests | Purpose |
|--------|-------|-------|---------|
| `backend.rs` | ~440 | 17 | AgentGovernanceBackend trait + InMemoryAgentGovernanceBackend |
| `autonomy_controller.rs` | ~340 | 12 | AutonomyLevelController trait + 3 implementations |
| `tool_governance.rs` | ~340 | 12 | ToolUseGovernor trait + 3 implementations |
| `delegation_manager.rs` | ~330 | 12 | DelegationGovernor trait + DepthLimitedDelegationGovernor + 2 implementations |
| `agent_export.rs` | ~430 | 11 | AgentGovernanceExporter trait + 5 format implementations |
| `agent_stream.rs` | ~310 | 10 | AgentLifecycleEventSubscriber trait + registry + filtering |
| `agent_metrics.rs` | ~310 | 11 | AgentGovernanceMetricsCollector trait + InMemoryAgentGovernanceMetricsCollector |

### Trait Contracts

- **AgentGovernanceBackend**: 20 methods — store/retrieve governance profiles, list by status, profile_count, store/retrieve autonomy configurations, list by agent, store/retrieve tool policies, list by agent, store/retrieve delegation chains, list by delegator, store/retrieve governance snapshots, list by agent, flush/backend_info. InMemoryAgentGovernanceBackend reference implementation. StoredAgentGovernanceStatus 4-variant (Active/Suspended/UnderReview/Decommissioned), StoredToolPolicyDecision 4-variant (Allow/Deny/RequireApproval/AllowWithConstraints), StoredDelegationChainStatus 4-variant (Active/Completed/Revoked/DepthLimitExceeded).
- **AutonomyLevelController**: 7 methods — evaluate_autonomy/recommend_level_change/check_escalation_required/register_agent_level/list_active_levels/controller_id/is_active. AutonomyDecision 5-variant (Permit/Deny/Escalate/RequireHumanApproval/DegradeAutonomy). AutonomyEvaluation with escalation_target. LevelChangeRecommendation with confidence as String. InMemoryAutonomyLevelController (deny-pattern matching), AlwaysEscalateAutonomyController (EU AI Act Article 14 — every action requires human approval), NullAutonomyLevelController.
- **ToolUseGovernor**: 6 methods — evaluate_tool_request/register_tool_policy/remove_tool_policy/list_tool_policies/governor_id/is_active. ToolGovernanceDecision 5-variant (Permit/Deny/RequireApproval/RateLimited/DeferToHuman). ToolGovernanceEvaluation with remaining_invocations. ToolPolicyEntry with max_invocations. InMemoryToolUseGovernor (invocation counting, rate limiting, policy replacement), DenyAllToolUseGovernor (agents with no tool access — rejects policy registration), NullToolUseGovernor.
- **DelegationGovernor**: 6 methods — evaluate_delegation_request/record_delegation_chain/check_depth_limit/list_delegation_chains/governor_id/is_active. DelegationRequestDecision 5-variant (Approve/Deny/RequireApproval/DepthLimitExceeded/DeferToHuman). DelegationEvaluation with current_depth/max_depth. InMemoryDelegationGovernor (denied_delegatees list, depth enforcement), DepthLimitedDelegationGovernor<G> (composable wrapper enforcing depth limit before delegating to inner governor), NullDelegationGovernor.
- **AgentGovernanceExporter**: 7 methods — export_agent_profile/export_autonomy_config/export_tool_policy_report/export_delegation_chain_report/export_batch/format_name/content_type. JsonAgentGovernanceExporter (full JSON), AgentCardExporter (agent directory card format), HumanOversightReportExporter (EU AI Act Article 14 Markdown compliance report), AutonomyAssessmentExporter (NIST AI RMF aligned JSON with govern/map/manage sections), DelegationChainExporter (Markdown delegation chain report).
- **AgentLifecycleEventSubscriber**: 3 methods — on_agent_governance_event/subscriber_id/is_active. AgentLifecycleEventSubscriberRegistry with register/notify/notify_batch/active_count/remove_inactive. AgentGovernanceEventCollector reference implementation. FilteredAgentLifecycleEventSubscriber<S> with agent_id/event_type/severity filters using let-chains. AgentGovernanceLifecycleEventType 20-variant enum.
- **AgentGovernanceMetricsCollector**: 7 methods — compute_autonomy_escalation_rate/compute_tool_denial_rate/compute_delegation_depth_average/list_most_denied_tools/compute_human_oversight_frequency/collector_id/is_active. AgentGovernanceMetricSnapshot with all computed values as String for Eq derivation. InMemoryAgentGovernanceMetricsCollector (computes from escalation/denial/delegation/oversight records), NullAgentGovernanceMetricsCollector.

### Modified Files

- **audit.rs**: 24 new AgentEventType L3 variants with struct fields. Display impl delegates L3 variants to type_name(). Added type_name()/kind() methods covering all 57 variants (33 L1/L2 + 24 L3). Classification methods: is_backend_event/is_autonomy_governance_event/is_tool_governance_event/is_delegation_governance_event/is_governance_export_event/is_governance_metrics_event. Test constructs every L3 variant and asserts non-empty Display and kind() output.
- **error.rs**: 3 new AgentError variants: SerializationFailed(String), GovernanceProfileNotFound(String), DelegationChainNotFound(String). Display impl updated. Test updated to cover all 24 variants.
- **lib.rs**: 7 new module declarations under Layer 3 section. Layer 3 re-exports grouped under `// ── Layer 3 re-exports ──` comment.

### Naming Collision Resolutions

| L1/L2 type | L3 type | Rationale |
|---|---|---|
| `AutonomyLevel` (L1 enum: 7-variant fixed taxonomy None/Observe/Suggest/ActLowRisk/ActMediumRisk/ActHighRisk/Full) | L3 stored types use opaque `String` for autonomy level | L1 defines compile-time taxonomy; L3 uses opaque strings for extensibility (ISO/IEC 22989 autonomy levels vary by domain) |
| `DelegationManager` (L1 concrete struct: lifecycle management) | `DelegationGovernor` (L3 trait: policy governance) | L1 manages delegation lifecycle (accept/reject/complete/revoke); L3 governs delegation policy (approve/deny/depth-limit). Different semantic axis |
| `ToolRegistry` (L1 concrete struct: tool registration/invocation) | `ToolUseGovernor` (L3 trait: tool-use policy) | L1 manages tool definitions and invocations; L3 governs per-agent tool access decisions |
| `AgentRegistry` (L1 concrete struct: agent identity) | `AgentGovernanceBackend` (L3 trait: persistent governance storage) | L1 manages in-memory agent registration; L3 manages pluggable persistent storage of governance artifacts |
| `DelegationCreated`/`DelegationCompleted` (L1 audit variants) | `StoredDelegationChainRecorded`/`DelegationGovernanceApproved`/`DelegationGovernanceDenied` (L3 audit variants) | L1 tracks delegation lifecycle events; L3 tracks governance policy decisions. `Stored` prefix for backend persistence, `Governance` qualifier for policy evaluation |
| `AutonomyBoundaryViolation` (L1 audit variant) | `AutonomyLevelEvaluated`/`AutonomyEscalationTriggered` (L3 audit variants) | L1 detects boundary violations; L3 evaluates autonomy levels and triggers escalation. Different semantic scope |

### Design Decisions

- **rune-agents is not an agent runtime**: rune-agents provides governance infrastructure for agents — autonomy control, tool-use policy, delegation governance, metrics. It does not implement agent execution, planning, memory, or tool invocation. Those belong in runtime crates that consume rune-agents governance contracts.
- **Autonomy level is opaque string in L3**: L1 defines a 7-level AutonomyLevel enum. L3 stored types and controller trait use opaque strings because autonomy taxonomies vary by domain (ISO/IEC 22989 defines different levels than SAE J3016 or NIST AI RMF). L3 should not force a specific taxonomy on backend storage.
- **AlwaysEscalateAutonomyController first-class**: EU AI Act Article 14 requires human oversight for high-risk AI systems. Having a reference implementation that escalates every action to human approval directly reduces compliance burden for high-risk deployments.
- **DenyAllToolUseGovernor first-class**: Some agents should never have tool access (observation-only, suggest-only). Having a dedicated implementation that rejects all tool requests and refuses policy registration prevents accidental tool grants.
- **DepthLimitedDelegationGovernor composable wrapper**: Follows the composable wrapper pattern established across 9+ libraries. Wraps any DelegationGovernor and enforces depth limit before delegating to inner governor. Prevents unbounded delegation chains.
- **DelegationGovernor not DelegationManager**: L1 already has a `DelegationManager` struct that manages delegation lifecycle. The L3 trait governs delegation policy decisions. Different name avoids both module-level and type-level collision.
- **Agent governance metrics use String for all values**: autonomy_escalation_rate, tool_denial_rate, delegation_depth_average, human_oversight_frequency are all String fields. Enables Eq derivation for deterministic testing.
- **Human oversight report distinct from agent card**: Agent cards describe agent capabilities for directory purposes. Human oversight reports address EU AI Act Article 14 compliance. Different audiences, different content structure.

### Four-Pillar Alignment

| Pillar | Alignment |
|--------|-----------|
| **Transparency** | All backend operations emit structured audit events. Governance profiles exportable in 5 formats including agent cards and NIST AI RMF assessments. Lifecycle event streaming enables real-time observability of autonomy evaluation, tool governance, and delegation decisions. Governance metrics provide quantified visibility into agent governance posture. |
| **Accountability** | Every governance profile carries owner metadata. Autonomy evaluations record decision justification. Delegation chains track delegator/delegatee/depth/task. Human oversight reports document Article 14 compliance. Governance snapshots capture point-in-time governance state. |
| **Fairness** | ToolUseGovernor applies consistent per-agent tool policies with explicit justification. DelegationGovernor enforces uniform depth limits across all delegation chains. AutonomyLevelController evaluates all agents against the same deny patterns and escalation rules. |
| **Safety** | AlwaysEscalateAutonomyController ensures human oversight for all actions (EU AI Act Article 14). DepthLimitedDelegationGovernor prevents unbounded delegation chains. DenyAllToolUseGovernor prevents accidental tool grants. Governance metrics track escalation rates and tool denial rates for safety monitoring. |

### Integration Points

- **rune-safety**: Safety envelopes may reference agent autonomy constraints; rune-agents provides the autonomy evaluation while rune-safety provides envelope monitoring and emergency shutdown
- **rune-permissions**: Permission decisions may reference agent governance profiles; rune-agents governs agent-specific autonomy while rune-permissions governs identity-based access control
- **rune-explainability**: When rune-agents escalates a decision, rune-explainability can explain why via reasoning traces and feature attributions; the escalation mechanism lives in rune-agents, the explanation in rune-explainability
- **rune-detection**: Detection alerts may trigger autonomy level changes; rune-agents defines the autonomy governance while rune-detection defines the detection signal
- **rune-provenance**: Delegation chains are provenance-relevant; rune-agents tracks the governance policy while rune-provenance tracks the lineage
- **rune-framework**: Framework requirements reference rune-agents capabilities via opaque strings (e.g. referenced_library: "rune-agents", referenced_capability: "AutonomyLevelController") for EU AI Act/NIST AI RMF compliance

---

## rune-networking-ext — Layer 3 (Trait Boundaries / Serialization Formats / Abstraction Interfaces)

**Date**: 2026-04-21
**Commit**: `feat(rune-networking-ext): Layer 3 — network governance backend, TLS policy enforcer, network segmentation verifier, DNS security governor, network governance exporters, network event streaming, network governance metrics collector`

### Scope

7 new modules, 22 audit variants, 4 error variants, lib.rs re-exports. Layer 3 delivers trait boundaries, serialization formats, and abstraction interfaces for network governance — NOT concrete connectors or adapters.

### New Modules

| Module | Key Types | Purpose |
|---|---|---|
| `backend.rs` | `NetworkGovernanceBackend` trait, `StoredTlsPolicy`, `StoredConnectionRecord`, `StoredSegmentationPolicy`, `StoredDnsPolicy`, `StoredCertificateRecord`, `StoredNetworkGovernanceSnapshot`, `InMemoryNetworkGovernanceBackend` | Persistence abstraction for network governance data |
| `tls_policy_enforcer.rs` | `TlsPolicyEnforcer` trait, `TlsPolicyDecision`, `TlsCertificateIssue`, `CertificateExpirationStatus`, `InMemoryTlsPolicyEnforcer`, `StrictTlsPolicyEnforcer<E>`, `NullTlsPolicyEnforcer` | TLS connection/certificate evaluation against governance policies |
| `segmentation_verifier.rs` | `NetworkSegmentationVerifier` trait, `SegmentationVerificationDecision`, `SegmentationVerification`, `SegmentationImprovement`, `InMemoryNetworkSegmentationVerifier`, `DenyByDefaultSegmentationVerifier<V>`, `NullNetworkSegmentationVerifier` | Network segmentation policy verification |
| `dns_security.rs` | `DnsSecurityGovernor` trait, `DnsQueryDecision`, `DnsQueryEvaluation`, `DnssecStatus`, `ResolverComplianceResult`, `InMemoryDnsSecurityGovernor`, `BlocklistDnsSecurityGovernor<G>`, `NullDnsSecurityGovernor` | DNS security governance with DNSSEC and DoH/DoT compliance |
| `network_export.rs` | `NetworkGovernanceExporter` trait, `JsonNetworkGovernanceExporter`, `PciDssNetworkComplianceExporter`, `CjisNetworkSecurityExporter`, `ZeroTrustAssessmentExporter`, `TlsCertificateInventoryExporter` | Export network governance data to compliance formats |
| `network_stream.rs` | `NetworkGovernanceEventSubscriber` trait, `NetworkGovernanceLifecycleEventType` (20 variants), `NetworkGovernanceEventSubscriberRegistry`, `NetworkGovernanceEventCollector`, `FilteredNetworkGovernanceEventSubscriber<S>` | Network governance lifecycle event streaming |
| `network_metrics.rs` | `NetworkGovernanceMetricsCollector` trait, `NetworkGovernanceMetricSnapshot`, `InMemoryNetworkGovernanceMetricsCollector`, `NullNetworkGovernanceMetricsCollector` | Compute network governance metrics (TLS compliance, mTLS adoption, certificate health, segmentation compliance, DNS block rate) |

### Audit Variants (22 new → 52 total)

Backend: `StoredTlsPolicyCreated`, `StoredConnectionRecordCreated`, `StoredSegmentationPolicyCreated`, `StoredDnsPolicyCreated`, `StoredCertificateRecordCreated`, `StoredNetworkGovernanceSnapshotCaptured`, `NetworkGovernanceFlushed`, `NetworkGovernanceBackendInfo`

TLS governance: `TlsPolicyConnectionEvaluated`, `TlsPolicyNonCompliant`, `TlsCertificateGovernanceEvaluated`, `TlsCertificateIssueDetected`

Segmentation governance: `SegmentationFlowVerified`, `SegmentationFlowDeniedByVerifier`, `SegmentationComplianceAssessed`

DNS governance: `DnsQueryEvaluatedByGovernor`, `DnsQueryBlockedByGovernor`, `DnsResolverComplianceChecked`

Export: `NetworkGovernanceExported`, `NetworkGovernanceExportFailed`

Metrics: `NetworkGovernanceMetricsComputed`

Stream: `NetworkGovernanceEventPublished`

Added `type_name()`, `kind()`, and classification methods (`is_backend_event`, `is_tls_governance_event`, `is_segmentation_governance_event`, `is_dns_governance_event`, `is_governance_export_event`, `is_governance_metrics_event`).

### Error Variants (4 new → 19 total)

`SerializationFailed`, `TlsPolicyNotFound`, `SegmentationPolicyNotFound`, `DnsPolicyNotFound`

### Naming Collision Resolution

| L1 Name | L3 Name | Reason |
|---|---|---|
| `DnsGovernor` (struct) | `DnsSecurityGovernor` (trait) | Avoid collision; documented in file header |
| `SegmentationDecision` (struct) | `SegmentationVerificationDecision` (enum) | Different semantics: L1 is `{allowed: bool}`, L3 is 5-variant enum |
| `TlsPolicy` (struct) | `StoredTlsPolicy` (serializable) | L3 is for backend persistence |
| `TlsVersion` (4 variants) | `StoredMinTlsVersion` (Tls12/Tls13) | Reduced set for policy minimum |
| `CertificateStatus` | `StoredCertificateRecordStatus` | Different variant set |
| `SegmentationAction` (Allow/Deny/Audit) | `StoredSegmentationDefaultAction` (Allow/Deny/LogOnly) | Different semantics |
| `DnsDecision` (struct) | `DnsQueryDecision` (enum) + `DnsQueryEvaluation` | Richer governance model |
| L1 `DnsQueryBlocked` (audit) | L3 `DnsQueryBlockedByGovernor` | Differentiated by "ByGovernor" suffix |
| L2 `SegmentationViolationDetected` (audit) | L3 `SegmentationFlowDeniedByVerifier` | Differentiated by "ByVerifier" suffix |

### Industry Standards

- **TLS 1.3** (RFC 8446): `StrictTlsPolicyEnforcer` enforces minimum TLS 1.3
- **Certificate Transparency** (RFC 6962): `StrictTlsPolicyEnforcer` requires CT logging; `TlsCertificateIssue::NoCertificateTransparency`
- **DNSSEC** (RFC 4033-4035): `DnssecStatus` enum, `require_dnssec` config, resolver compliance checks
- **DoH/DoT** (RFC 8484/7858): `ResolverComplianceResult` tracks `supports_doh`/`supports_dot`
- **PCI DSS v4.0 Requirement 1**: `PciDssNetworkComplianceExporter`
- **CJIS Security Policy v6.0 Policy Area 6**: `CjisNetworkSecurityExporter`
- **NIST SP 800-207 Zero Trust**: `ZeroTrustAssessmentExporter`
- **mTLS**: `InMemoryTlsPolicyEnforcer` `require_client_cert`, mTLS adoption rate metric

### Composable Wrappers

| Wrapper | Wraps | Behavior |
|---|---|---|
| `StrictTlsPolicyEnforcer<E>` | `TlsPolicyEnforcer` | Enforces TLS 1.3 minimum + Certificate Transparency |
| `DenyByDefaultSegmentationVerifier<V>` | `NetworkSegmentationVerifier` | Overrides non-Allowed decisions to Denied |
| `BlocklistDnsSecurityGovernor<G>` | `DnsSecurityGovernor` | Adds additional domain blocklist layer |

### Four-Pillar Alignment

| Pillar | Evidence |
|---|---|
| **Transparency** | All exporters produce human-readable output. `type_name()` and `kind()` enable programmatic event filtering. 20-variant lifecycle event type provides fine-grained observability. |
| **Accountability** | Backend stores complete TLS policies, connection records, segmentation policies, DNS policies, certificate records with timestamps and metadata. Governance snapshots capture point-in-time state. |
| **Fairness** | TLS enforcement applies consistently — `InMemoryTlsPolicyEnforcer` evaluates all connections against same version/cipher/cert rules. Segmentation verification uses same allowed/denied flow lists for all zones. DNS governance applies blocklist/allowlist uniformly. |
| **Safety** | `StrictTlsPolicyEnforcer` prevents TLS downgrade below 1.3. `DenyByDefaultSegmentationVerifier` prevents unintended cross-zone access. `BlocklistDnsSecurityGovernor` adds defense-in-depth DNS blocking. Certificate expiration monitoring enables proactive renewal. |

### Validation

- **Tests**: 253 passed (87 L3 tests across 7 modules + 8 audit tests + updated error test)
- **Clippy**: Zero warnings in all L3 files
- **Compilation**: Clean build with no errors
