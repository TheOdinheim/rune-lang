# rune-privacy

Privacy engineering for the RUNE governance ecosystem.

## Overview

`rune-privacy` provides PII detection, anonymization, differential privacy, consent management, data subject rights (GDPR/CCPA), purpose limitation, retention policies, privacy impact assessment, and a privacy-specific audit log. Every operation is designed to leave a verifiable trail and enforce the four RUNE pillars.

## Modules

| Module | Purpose |
|--------|---------|
| `pii` | `PiiCategory` (21 variants incl. GDPR Art. 9 special categories), heuristic detection, pattern library, sensitivity levels |
| `anonymize` | Redaction, masking, generalization, SHA3-256 hashing, HMAC pseudonymization, Laplace/Gaussian noise, k-anonymity, l-diversity, t-closeness, pipeline |
| `differential` | `(ε, δ)`-DP budget accounting, Laplace/Gaussian/Exponential mechanisms, count/sum/average/histogram queries |
| `purpose` | `LegalBasis` (GDPR Art. 6), `Purpose` registry, data tagging, purpose-limitation checks, data-minimization checks |
| `consent` | Consent lifecycle, withdrawal, evidence (method/IP/UA/signature), scope, expiry, history |
| `rights` | GDPR Art. 15–22 and CCPA §1798.105/110/120 data-subject rights with 30/45-day deadline tracking |
| `retention` | Retention policies by category/purpose/classification, most-restrictive enforcement, expiry actions |
| `impact` | Privacy Impact Assessment (PIA/DPIA) builder with risk rating, mitigations, recommendations |
| `audit` | `PrivacyAuditEvent` log with filters by subject, type, time, violations, consent events |
| `error` | `PrivacyError` with 14 typed variants |

## Four-Pillar Alignment

- **Security Baked In**: PII detection and classification by default; anonymization primitives (k-anonymity, l-diversity, t-closeness, differential privacy) as first-class citizens.
- **Assumed Breach**: Every privacy operation is audit-logged; consent evidence is retained for legal defensibility; DP budgets bound worst-case leakage.
- **Zero Trust Throughout**: Purpose limitation enforced at use-site; data minimization checks at collection-site; consent verified before processing.
- **No Single Points of Failure**: Retention policies auto-expire stale data; rights requests track deadlines independently; PIAs surface unmitigated risks.

## Usage

```rust
use rune_privacy::*;
use rune_identity::IdentityId;

// Detect PII in a record
let detector = PiiDetector::new();
let findings = detector.detect_in_text("Contact alice@example.com or 555-123-4567");

// Record consent
let mut store = ConsentStore::new();
let purpose = Purpose::new("analytics", "Analytics", LegalBasis::Consent);
// store.record_consent(...);

// Track a data subject right request with GDPR deadline
let mut rights = RightsManager::new();
let req = rights.submit_request(
    IdentityId::new("user:alice"),
    SubjectRight::Access,
    1_700_000_000_000,
);

// Allocate a differential privacy budget
let mut engine = DpEngine::new(PrivacyBudget::standard());
// engine.execute_count(...);
```

## Tests

104 tests covering all modules, including PII detection heuristics, DP budget accounting, k-anonymity/l-diversity/t-closeness, consent lifecycle, GDPR/CCPA deadlines, retention enforcement, and PIA risk calculation.
