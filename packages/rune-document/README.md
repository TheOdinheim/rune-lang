# rune-document

Compliance document generation from live governance data — GDPR Article 30, NIST AI RMF, CMMC, privacy impact assessments, and system security plans for the RUNE governance ecosystem.

## Overview

`rune-document` generates compliance documentation from live system state. Instead of hand-writing documents that drift from reality, it pulls data from the governance libraries and produces structured, versioned compliance artifacts. Regulators don't want to read audit logs — they want records of processing activities, risk management profiles, maturity assessments, and security plans in their own vocabulary. This crate translates the RUNE ecosystem's internal data into the specific formats each regulatory framework requires.

## Modules

| Module | Purpose |
|--------|---------|
| `document` | Core Document type with DocumentId (newtype), DocumentVersion (semver with bump), DocumentStatus lifecycle (Draft/UnderReview/Approved/Published/Superseded/Archived), ComplianceFramework (12 frameworks), DocumentSection with fields and compliance status, DocumentStore with approve/archive/supersede/completion_rate |
| `gdpr` | GDPR Article 30 records of processing activities — ControllerInfo, ProcessingActivity with legal basis/data categories/recipients/transfers/retention, GdprDocumentBuilder producing 7 sections matching Art. 30 structure, validate() for gap identification |
| `nist` | NIST AI RMF profile generation — NistFunction/NistCategory/NistSubcategory hierarchy, MaturityLevel (6 levels: NotImplemented through Optimizing), ProfileType (Current/Target/Gap), ai_rmf_skeleton() with 4 functions and 19 categories |
| `cmmc` | CMMC maturity level assessment — CmmcLevel (1-3), CmmcDomain/CmmcPractice, score calculation, unmet_practices detection, level1_skeleton() with 6 domains |
| `pia` | Privacy Impact Assessment / DPIA — PiaDataFlow, PiaRisk with likelihood/impact/residual, PiaMitigation, PiaConsultation, NecessityAssessment, risk_matrix() and high_risks() for Art. 36 consultation triggers |
| `ssp` | System Security Plan — SystemType (4 variants), ImpactLevel, SecurityControlEntry with ImplementationStatus (5 variants), controls_by_family grouping, implementation_rate calculation |
| `template` | Document templates and section definitions — 5 built-in templates (GDPR Art. 30, NIST AI RMF, CMMC, DPIA, SSP), TemplateRegistry, instantiate_template() creates empty Document from template |
| `renderer` | Document rendering — PlainText/Markdown/Json output, completion_summary with missing field tracking and compliance status aggregation |
| `audit` | Document audit events — 10 event types (Created/Updated/Approved/Published/Archived/Superseded/TemplateInstantiated/ComplianceGapFound/ReviewDue/Rendered), document/type/approval/gap filters |
| `error` | DocumentError enum with 9 typed variants |

## Four-pillar alignment

- **Security Baked In**: Every compliance document is versioned with full lifecycle tracking; required fields are enforced at the template level; ComplianceStatus tracks compliance state per section; gap validation identifies missing requirements before documents reach regulators.
- **Assumed Breach**: Document versioning and supersede mechanics create an immutable audit trail; completion_summary exposes unfilled required fields that could mask non-compliance; the audit log tracks every document action (creation, approval, rendering) to detect unauthorized modifications.
- **Zero Trust Throughout**: No document is trusted as complete without explicit field-by-field verification; DocumentStore.completion_rate() quantifies how much of a document is actually filled; templates enforce that all framework-required sections exist even if empty; approval requires explicit approver identity and timestamp.
- **No Single Points of Failure**: Five independent document generators (GDPR, NIST, CMMC, PIA, SSP) each produce framework-specific output; the template system provides a second path to document creation; three render formats (text, markdown, JSON) ensure documents are accessible regardless of tooling; ComplianceFramework supports 12 frameworks with Custom fallback.

## Test summary

90 tests covering all modules:

| Module | Tests |
|--------|-------|
| document | 21 |
| gdpr | 10 |
| nist | 8 |
| cmmc | 9 |
| pia | 9 |
| ssp | 9 |
| template | 11 |
| renderer | 10 |
| audit | 5 |
| error | 1 |
