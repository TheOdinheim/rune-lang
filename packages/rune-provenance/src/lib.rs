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

pub use artifact::{Artifact, ArtifactId, ArtifactStore, ArtifactType, ArtifactVersion};
pub use audit::{ProvenanceAuditEvent, ProvenanceAuditLog, ProvenanceEventType};
pub use error::ProvenanceError;
pub use graph::{
    EdgeRelationship, ProvenanceEdge, ProvenanceGraph, ProvenanceNode, ProvenanceNodeType,
};
pub use lineage::{DataLineage, LineageId, LineageRegistry, LineageSource, SourceRelationship};
pub use model::{
    DeploymentRecord, DeploymentStatus, EvaluationRecord, FineTuningRecord, ModelArchitecture,
    ModelProvenance, ModelProvenanceId, ModelRegistry, TrainingRecord,
};
pub use slsa::{
    BuildInvocation, SlsaCompleteness, SlsaLevel, SlsaMaterial, SlsaMetadata, SlsaPredicate,
    SlsaProvenanceStore,
};
pub use supply_chain::{
    Dependency, DependencyId, DependencySource, SupplyChain, VulnerabilityStatus,
};
pub use transform::{
    ExecutionEnvironment, Transformation, TransformType, TransformationId, TransformationLog,
    TransformationRef,
};
pub use verification::{
    ProvenanceVerifier, VerificationCheck, VerificationCheckType, VerificationResult,
    VerificationStatus,
};
