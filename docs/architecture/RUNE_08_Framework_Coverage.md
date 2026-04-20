# RUNE Architecture Reference — Framework Coverage Map

**Document ID:** ODIN-ARCH-FWCOV-2026-001
**DO NOT DELETE THIS FILE**

---

## Purpose

This document maps every regulatory and compliance framework referenced across
the RUNE governance library stack to its actual implementation depth. It serves
as a single point of truth for answering: "Which framework controls does RUNE
encode, how deeply, and where are the gaps?"

---

## Encoding Depth Taxonomy

| Depth | Definition |
|---|---|
| **Structural** | Full type-level encoding of the framework's control hierarchy, scoring algorithms, level definitions, and evidence collection. Usable as a standalone compliance engine. |
| **Operational** | Working enforcement logic (checks, gates, deadlines) but not exhaustive coverage of every control in the framework. |
| **Skeleton** | Data structures and registry entries exist. Controls are enumerated but lack enforcement logic. Suitable for cataloguing, not for pass/fail decisions. |
| **Reference-Only** | The framework is mentioned in string constants, article citations, or documentation but has no dedicated type-level encoding. |

---

## 1. Framework Coverage Summary

| Framework | Crate(s) | Depth | Controls Encoded | Key Modules |
|---|---|---|---|---|
| SLSA v1.0 | rune-provenance | Structural | L0-L4 levels, attestation, verification, evidence | `slsa.rs` |
| CVSS v3.1 | rune-security | Structural | Base (AV/AC/PR/UI/S/C/I/A), Temporal, Environmental, AI-specific impact | `vulnerability.rs` |
| IEC 61508 (SIL) | rune-safety | Structural | SIL 0-4, failure rate targets, test coverage thresholds, independent verification | `integrity.rs` |
| DO-178C (DAL) | rune-safety | Structural | DAL E-A, structural coverage requirements (statement through MC/DC + object code) | `integrity.rs` |
| ISO 26262 (ASIL) | rune-safety | Structural | QM, ASIL A-D | `integrity.rs` |
| GDPR | rune-privacy, rune-explainability | Operational | Art. 15-22 (data subject rights), consent lifecycle, 30-day deadlines, Art. 22 automated decisions | `rights.rs`, `consent.rs`, `compliance.rs` |
| CCPA | rune-privacy | Operational | Opt-out (s1798.120), Delete (s1798.105), Know (s1798.110), 45-day deadlines | `rights.rs` |
| EU AI Act | rune-explainability, rune-framework | Operational / Skeleton | Art. 13 transparency, Art. 14 human oversight checks (Operational in explainability); Art. 6/9/10/13/14/15 control skeletons (Skeleton in framework) | `compliance.rs`, `l2_framework_registry.rs` |
| NIST AI RMF 1.0 | rune-framework | Skeleton | 8 controls across Govern/Map/Measure/Manage categories | `l2_framework_registry.rs` |
| SOC 2 Type II | rune-framework | Skeleton | 6 controls across 5 trust service criteria (Security, Availability, Processing Integrity, Confidentiality, Privacy) | `l2_framework_registry.rs` |

---

## 2. Per-Framework Detail

### 2.1 SLSA v1.0 (Supply-chain Levels for Software Artifacts)

**Crate:** `rune-provenance` | **Depth:** Structural | **Module:** `slsa.rs`

**What is encoded:**

- **Level definitions:** `SlsaLevel` enum (L0-L4) with `Ord` for level comparison
- **Provenance predicates:** `SlsaPredicate` with build type, builder ID, invocation details, materials, and metadata
- **Materials tracking:** `SlsaMaterial` with URI and multi-algorithm digest map
- **Completeness model:** `SlsaCompleteness` (parameters, environment, materials)
- **Level assessment:** `SlsaProvenanceStore::assess_level` — automated L0-L4 classification based on builder authentication, completeness, reproducibility, and two-party review
- **Attestation generation:** `generate_attestation` produces SHA3-256-hashed attestations
- **Attestation verification:** `verify_attestation` checks hash integrity, materials presence, and builder identity
- **Evidence-based assessment:** `assess_with_evidence` returns per-requirement satisfaction with `missing_for_next_level` gap analysis

**What is not encoded:**

- Signed attestation bundles (DSSE envelope)
- Integration with Sigstore or other transparency logs
- Builder identity verification against a trust root

### 2.2 CVSS v3.1 (Common Vulnerability Scoring System)

**Crate:** `rune-security` | **Depth:** Structural | **Module:** `vulnerability.rs`

**What is encoded:**

- **Base metrics:** `AttackVector` (Network/Adjacent/Local/Physical), `AttackComplexity` (Low/High), `PrivilegesRequired` (None/Low/High with scope-change adjustment), `UserInteraction` (None/Required), `VulnScope` (Unchanged/Changed), `Impact` (None/Low/High)
- **Score weights:** Each metric variant carries its CVSS v3.1 numerical weight
- **AI-specific extension:** `AiImpact` adds model integrity, training data integrity, inference reliability, governance bypass risk, and data exfiltration risk
- **Vulnerability store:** Full lifecycle tracking with `VulnerabilityId`, severity classification, and threat category linkage

**What is not encoded:**

- CVSS vector string parser (e.g., `CVSS:3.1/AV:N/AC:L/...`)
- Temporal metrics (exploit code maturity, remediation level, report confidence) as separate types
- Environmental metric group score modifiers

### 2.3 IEC 61508 / DO-178C / ISO 26262 (Safety Standards)

**Crate:** `rune-safety` | **Depth:** Structural | **Module:** `integrity.rs`

**IEC 61508 (SafetyIntegrityLevel):**
- SIL 0-4 with `failure_rate_target()` (1e-6 to 1e-9 per hour)
- `min_test_coverage()` (90% to 99.9%)
- `requires_independent_verification()` (SIL 3-4)

**DO-178C (DesignAssuranceLevel):**
- DAL E-A with `structural_coverage_required()` (none through MC/DC + object code)
- `independence_required()` (DAL A-B)

**ISO 26262 (AutomotiveSafetyLevel):**
- QM, ASIL A-D with `Ord` for severity comparison

**Cross-standard:**
- `SafetyClassification` unifies SIL + DAL + ASIL + custom level in a single assessment
- `highest_level_name()` produces composite label
- `requires_formal_verification()` checks SIL 4 / DAL A / ASIL D

**What is not encoded:**

- Hazard and risk analysis (HARA) workflow
- Safety case argumentation structure (GSN/CAE)
- Verification plan templates per level
- Quantitative failure rate calculation

### 2.4 GDPR (General Data Protection Regulation)

**Crate:** `rune-privacy` | **Depth:** Operational | **Modules:** `rights.rs`, `consent.rs`

**What is encoded:**

- **Data subject rights (Art. 15-22):** `SubjectRight` enum with `regulation_article()` returning exact article citations — Access (Art. 15), Rectification (Art. 16), Erasure (Art. 17), Restrict Processing (Art. 18), Data Portability (Art. 20), Object to Processing (Art. 21), Automated Decision Exemption (Art. 22)
- **Request lifecycle:** `RightsManager` with `submit_request`, `update_status`, `complete_request`, overdue detection
- **Deadline enforcement:** `GDPR_DEADLINE_MS` = 30 days, applied automatically on request submission
- **Consent management:** `ConsentId`, `ConsentScope` (Specific/Category/AllData), `ConsentStatus` (Active/Withdrawn/Expired/Superseded), consent evidence with `ConsentMethod`
- **Art. 22 cross-reference:** Also checked in `rune-explainability` via `check_gdpr_art22()` which validates factor documentation and counterfactual analysis

**What is not encoded:**

- Data Protection Impact Assessment (DPIA) workflow
- Lawful basis documentation beyond consent
- Cross-border transfer safeguards (SCCs, adequacy decisions)
- Data breach notification (72-hour timeline)

### 2.5 CCPA (California Consumer Privacy Act)

**Crate:** `rune-privacy` | **Depth:** Operational | **Module:** `rights.rs`

**What is encoded:**

- **Consumer rights:** `CcpaOptOut` (s1798.120), `CcpaDelete` (s1798.105), `CcpaKnow` (s1798.110) with section citations
- **Deadline enforcement:** `CCPA_DEADLINE_MS` = 45 days
- **Request lifecycle:** Shares `RightsManager` infrastructure with GDPR rights

**What is not encoded:**

- Financial incentive disclosures
- "Do Not Sell" link requirement
- Service provider contract requirements
- Minor consent (under-16 opt-in)

### 2.6 EU AI Act

**Crate:** `rune-explainability` | **Depth:** Operational
**Crate:** `rune-framework` | **Depth:** Skeleton

**Operational (rune-explainability):**

- `RegulatoryFramework::EuAiActArt13` — transparency checks via `check_eu_ai_act()`: validates that outcome and factor documentation exist
- `RegulatoryFramework::EuAiActArt14` — human oversight checks: validates trace and evidence availability
- Returns `RegulatoryRequirement` with pass/fail and detail strings
- `ExplanationCompletenessCheck` scores explanation against 6 criteria (outcome, factors, evidence, counterfactual, audience adaptation, trace)

**Skeleton (rune-framework):**

- `eu_ai_act_skeleton()` defines `FrameworkDefinition` with 6 controls: ART-6 (risk classification), ART-9 (risk management), ART-10 (data governance), ART-13 (transparency), ART-14 (human oversight), ART-15 (accuracy/robustness)
- Controls have `ControlSeverity` (Critical/High) and `required` flags
- Categories: Risk Categories, Data Governance, Transparency, Human Oversight, Accuracy
- No enforcement logic — serves as a control catalogue

### 2.7 NIST AI RMF 1.0

**Crate:** `rune-framework` | **Depth:** Skeleton | **Module:** `l2_framework_registry.rs`

**What is encoded:**

- `nist_ai_rmf_skeleton()` with 8 controls across 4 NIST categories:
  - **Govern:** GOV-1 (governance structure, High, required), GOV-2 (risk management policies, High, required)
  - **Map:** MAP-1 (context mapping, Medium, required), MAP-2 (stakeholder identification, Medium, optional)
  - **Measure:** MEA-1 (performance measurement, High, required), MEA-2 (bias/fairness metrics, Critical, required)
  - **Manage:** MAN-1 (risk response actions, High, required), MAN-2 (continuous monitoring, Medium, required)

**What is not encoded:**

- Full NIST AI RMF subcategory structure (Govern has 6 subcategories, Map has 5, etc.)
- Playbook actions and suggested practices
- AI RMF Profile customisation
- Trustworthy AI characteristic mapping (valid, reliable, safe, secure, etc.)

### 2.8 SOC 2 Type II

**Crate:** `rune-framework` | **Depth:** Skeleton | **Module:** `l2_framework_registry.rs`

**What is encoded:**

- `soc2_skeleton()` with 6 controls across 5 Trust Service Criteria:
  - **Security:** CC-1 (logical/physical access controls), CC-2 (system monitoring)
  - **Availability:** A-1 (system availability monitoring)
  - **Processing Integrity:** PI-1 (processing completeness/accuracy)
  - **Confidentiality:** C-1 (confidentiality commitments)
  - **Privacy:** P-1 (privacy notice/consent)

**What is not encoded:**

- Full CC series (CC1.1 through CC9.9)
- Points of focus for each criterion
- Complementary subservice organisation controls (CSOCs)
- Type I vs Type II temporal distinction

---

## 3. Cross-Framework Equivalence Mappings

**Crate:** `rune-framework` | **Module:** `l2_control_mapping.rs`

The `ControlMappingStore` enables cross-framework evidence reuse with typed equivalence levels:

| Equivalence | Meaning |
|---|---|
| `Full` | Controls are interchangeable; evidence from one satisfies the other |
| `Substantial` | Major overlap; minor supplementary evidence may be needed |
| `Partial` | Related intent but different scope or granularity |
| `None` | No meaningful overlap |

**Built-in mappings (NIST AI RMF -> SOC 2):**

| Source | Target | Equivalence | Notes |
|---|---|---|---|
| GOV-1 | CC-1 | Partial | Governance maps partially to access controls |
| GOV-2 | CC-1 | Partial | Risk management policies overlap with security controls |
| MEA-1 | CC-2 | Substantial | Performance measurement substantially maps to monitoring |
| MAN-2 | CC-2 | Full | Continuous monitoring fully maps to SOC 2 monitoring |
| MAP-1 | PI-1 | Partial | Context mapping partially relates to processing integrity |

**Coverage API:**
- `mappings_from(framework, control_id)` — find equivalents for a specific control
- `mappings_between(source, target)` — all mappings between two frameworks
- `coverage_from_framework(source, target)` — fraction of mappings with non-None equivalence

---

## 4. Gap Analysis

### Frameworks with structural encoding but missing pieces

| Framework | Gap | Impact |
|---|---|---|
| SLSA | No DSSE/Sigstore integration | Attestations cannot be cryptographically verified against public transparency logs |
| CVSS | No vector string parser | Users must construct metric enums manually rather than parsing standard CVSS strings |
| CVSS | Temporal/Environmental metrics not fully separated | Scoring combines base with AI-specific but lacks standard temporal adjustment types |
| IEC 61508 | No HARA workflow | Hazard identification is outside scope; only classification is encoded |

### Frameworks with operational encoding but incomplete coverage

| Framework | Gap | Impact |
|---|---|---|
| GDPR | No DPIA workflow | Data protection impact assessments must be managed externally |
| GDPR | No breach notification timeline | 72-hour supervisory authority notification not tracked |
| GDPR | Lawful basis limited to consent | Legitimate interest, contract, legal obligation, vital interest, and public task not modelled |
| CCPA | No "Do Not Sell" enforcement | CCPA s1798.120 opt-out is tracked but link/UI requirement is not enforced |
| EU AI Act (explainability) | Only Art. 13/14 checked | Art. 6 risk classification, Art. 9 risk management, Art. 10 data governance, and Art. 15 accuracy have no enforcement logic |

### Frameworks at skeleton depth

| Framework | Gap | Impact |
|---|---|---|
| NIST AI RMF | 8 of ~70 subcategories encoded | Skeleton covers top-level categories only; no enforcement or evidence collection |
| SOC 2 | 6 of ~60+ controls encoded | Skeleton covers TSC categories only; detailed CC criteria not modelled |
| EU AI Act (framework) | Skeleton only | Registry entry with control metadata; no pass/fail evaluation |

### Cross-framework mapping gaps

| Mapping Direction | Status |
|---|---|
| NIST AI RMF -> SOC 2 | 5 mappings built-in |
| EU AI Act -> NIST AI RMF | Not yet mapped |
| EU AI Act -> SOC 2 | Not yet mapped |
| GDPR -> SOC 2 Privacy (P-1) | Not yet mapped |
| IEC 61508 -> DO-178C -> ISO 26262 | No cross-standard mappings (classified independently in `SafetyClassification`) |

---

## 5. Encoding Depth Upgrade Path

Priority upgrades to move frameworks from their current depth to the next level:

### Skeleton -> Operational

1. **NIST AI RMF:** Add enforcement functions that check whether a system meets each control (e.g., `check_nist_govern()` returning `Vec<RegulatoryRequirement>`). Expand from 8 to ~20 key subcategories. Estimated scope: new module in `rune-framework`.

2. **SOC 2:** Add evidence collection types and pass/fail checks for each TSC. Start with Security (CC series) as it overlaps most with existing `rune-security` capabilities. Estimated scope: new module in `rune-framework` plus cross-crate trait.

3. **EU AI Act (framework skeleton):** Connect the skeleton controls in `l2_framework_registry.rs` to the operational checks already implemented in `rune-explainability`. Add enforcement for Art. 6 risk classification, Art. 9 risk management, and Art. 15 accuracy/robustness. Estimated scope: bridge module or trait linking the two crates.

### Operational -> Structural

4. **GDPR:** Add `LawfulBasis` enum (consent, contract, legal obligation, vital interest, public task, legitimate interest), DPIA workflow types, and breach notification timeline tracking. Estimated scope: ~3 new modules in `rune-privacy`.

5. **CCPA:** Add financial incentive and minor consent types. Estimated scope: minor expansion of `rights.rs`.

6. **EU AI Act (explainability):** Extend beyond Art. 13/14 to cover Art. 6 risk classification with `RiskCategory` enum (Unacceptable/High/Limited/Minimal), Art. 10 data governance checks, and Art. 15 accuracy metrics. Estimated scope: ~2 new modules in `rune-explainability`.

### New framework candidates

7. **NIST CSF 2.0:** Natural complement to NIST AI RMF; shares Govern/Identify/Protect/Detect/Respond/Recover taxonomy. Could reuse `FrameworkRegistry` infrastructure.

8. **ISO 27001/27002:** Information security controls overlap significantly with SOC 2 and existing `rune-security` capabilities.

9. **HIPAA:** Healthcare data privacy rules could extend `rune-privacy` consent and rights infrastructure.

---

## Four-Pillar Alignment

| Pillar | Framework Coverage Contribution |
|---|---|
| **Security Baked In** | CVSS structural encoding ensures vulnerability severity is computed, not estimated. SLSA attestations provide supply-chain integrity evidence at build time. |
| **Assumed Breach** | GDPR breach response rights (Art. 17 erasure, Art. 18 restriction) and CCPA deletion rights provide post-incident data subject remediation. Safety standards (SIL/DAL/ASIL) encode failure-mode thresholds. |
| **No Single Points of Failure** | Cross-framework equivalence mappings prevent single-framework dependency. `SafetyClassification` unifies three independent safety standards. Multiple crates implement overlapping regulatory checks (GDPR in both privacy and explainability). |
| **Zero Trust Throughout** | EU AI Act Art. 13/14 checks enforce transparency at decision boundaries. SLSA level assessment requires progressive evidence accumulation. Consent is tracked with evidence and lifecycle status, not assumed. |
