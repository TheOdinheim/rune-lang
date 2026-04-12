# rune-provenance

Data lineage, model provenance, artifact versioning, and supply chain verification for the RUNE governance ecosystem.

## Overview

`rune-provenance` builds the chain-of-custody system that RUNE's governance layers depend on. Every piece of data, every model, every artifact gets a verifiable history: where it came from, what transformations were applied, who touched it, and whether the chain is intact. This crate provides the evidentiary foundation that `rune-truth`, `rune-explainability`, and `rune-document` build on.

## Modules

| Module | Purpose |
|--------|---------|
| `artifact` | Versioned, hash-identified artifacts with semver ordering and tag-based search |
| `lineage` | Data lineage: source → transform → output chains with BFS upstream/downstream tracing |
| `transform` | Transformation records: what was done to data at each step, by whom, in what environment |
| `model` | ML model provenance: architecture, training, evaluation, deployment, fine-tuning history |
| `supply_chain` | Dependency tracking with SHA3-256 build hashes, vulnerability status, lock verification |
| `slsa` | SLSA (Supply-chain Levels for Software Artifacts) L0–L4 provenance predicates |
| `graph` | Provenance DAG: BFS ancestry/descendancy, path finding, DFS cycle detection, depth |
| `verification` | Chain verification: 7 integrity checks with per-check status and confidence scoring |
| `audit` | Provenance audit events: 13 event types with artifact/type/time/category filters |
| `error` | ProvenanceError enum with 14 typed variants |

## Four-pillar alignment

- **Security Baked In**: Every artifact is hash-identified at registration; supply chain dependencies carry content hashes verified against stored values; SLSA level assessment runs automatically; the verifier checks 7 integrity properties without caller configuration.
- **Assumed Breach**: Provenance chains are independently verifiable — `verify_chain` walks upstream recursively so a compromised intermediate artifact is caught by hash mismatch or missing lineage; `SupplyChain::verify_lock` detects post-lock tampering; vulnerability tracking flags known-bad dependencies.
- **Zero Trust Throughout**: No artifact is trusted by default — `ProvenanceVerifier` requires positive evidence for each check (content hash present, lineage recorded, sources verified, transformations logged, supply chain clean, SLSA level met, license tracked); missing evidence is a failure, not a pass.
- **No Single Points of Failure**: Seven independent verification checks run in parallel — a gap in one (e.g., missing SLSA predicate) is reported independently without masking failures in others; the provenance graph stores relationships redundantly across lineage, transformation, and graph modules so data can be cross-validated.

## Usage

```rust
use rune_provenance::{
    Artifact, ArtifactStore, ArtifactType, ArtifactVersion,
    DataLineage, LineageRegistry,
    ProvenanceVerifier, VerificationStatus,
};

// Register an artifact
let mut store = ArtifactStore::new();
store.register(Artifact::new(
    "dataset-v1", "training-data", ArtifactType::Dataset,
    ArtifactVersion::new(1, 0, 0), "sha3-hash", "alice", 1000,
)).unwrap();

// Verify provenance chain
let verifier = ProvenanceVerifier::new(&store, &lineage, &transforms, &supply, &slsa);
let result = verifier.verify_artifact(&artifact_id, now);
assert_eq!(result.status, VerificationStatus::Verified);
```

## Test summary

99 tests covering all modules:

| Module | Tests |
|--------|-------|
| artifact | 15 |
| lineage | 10 |
| transform | 7 |
| model | 13 |
| supply_chain | 13 |
| slsa | 10 |
| graph | 13 |
| verification | 6 |
| audit | 8 |
| error | 1 |
