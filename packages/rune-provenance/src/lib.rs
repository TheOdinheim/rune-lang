// ═══════════════════════════════════════════════════════════════════════
// rune-provenance — data lineage, model provenance, artifact versioning,
// and supply chain verification for the RUNE governance ecosystem.
// ═══════════════════════════════════════════════════════════════════════

pub mod artifact;
pub mod audit;
pub mod error;
pub mod graph;
pub mod lineage;
pub mod model;
pub mod slsa;
pub mod supply_chain;
pub mod transform;
pub mod verification;

pub use artifact::{
    Artifact, ArtifactId, ArtifactStore, ArtifactType, ArtifactVersion,
    // Layer 2
    hash_artifact_content, hash_artifact_metadata, verify_artifact_hash,
    ArtifactMetadata, ContentAddressedStore, ArtifactIntegrityReport,
};
pub use audit::{ProvenanceAuditEvent, ProvenanceAuditLog, ProvenanceEventType};
pub use error::ProvenanceError;
pub use graph::{
    EdgeRelationship, ProvenanceEdge, ProvenanceGraph, ProvenanceNode, ProvenanceNodeType,
    // Layer 2
    ProvenanceGraphMetrics, ImpactAnalysis, LineageDiff,
};
pub use lineage::{
    DataLineage, LineageId, LineageRegistry, LineageSource, SourceRelationship,
    // Layer 2
    compute_record_hash, LineageRecord, LineageChainVerification, LineageChainStore,
};
pub use model::{
    DeploymentRecord, DeploymentStatus, EvaluationRecord, FineTuningRecord, ModelArchitecture,
    ModelProvenance, ModelProvenanceId, ModelRegistry, TrainingRecord,
    // Layer 2
    ModelComparison, compare_models, TrainingDataRecord, TrainingDataRegistry,
    ModelCard, generate_model_card,
};
pub use slsa::{
    BuildInvocation, SlsaCompleteness, SlsaLevel, SlsaMaterial, SlsaMetadata, SlsaPredicate,
    SlsaProvenanceStore,
    // Layer 2
    SlsaBuildMetadata, SlsaAttestation, generate_attestation, verify_attestation,
    SlsaAttestationVerification, SlsaEvidence, SlsaLevelEvidence, assess_with_evidence,
};
pub use supply_chain::{
    Dependency, DependencyId, DependencySource, SupplyChain, VulnerabilityStatus,
    // Layer 2
    VerifiedDependency, VerifiedDependencySource, verify_dependency_hash,
    DependencyGraph, BuildReproducibilityCheck, check_reproducibility,
};
pub use transform::{
    ExecutionEnvironment, Transformation, TransformType, TransformationId, TransformationLog,
    TransformationRef,
};
pub use verification::{
    ProvenanceVerifier, VerificationCheck, VerificationCheckType, VerificationResult,
    VerificationStatus,
};
