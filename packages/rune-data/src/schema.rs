// ═══════════════════════════════════════════════════════════════════════
// Schema governance and evolution types — schema records with versioned
// field definitions, compatibility assessment (backward/forward/
// breaking), breaking change detection with field-level granularity,
// and schema evolution policies requiring compatibility checks and
// migration plans.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::quality::QualitySeverity;

// ── SchemaFormat ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaFormat {
    JsonSchema,
    Avro,
    Protobuf,
    Parquet,
    Csv,
    Custom { name: String },
}

impl fmt::Display for SchemaFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JsonSchema => f.write_str("JsonSchema"),
            Self::Avro => f.write_str("Avro"),
            Self::Protobuf => f.write_str("Protobuf"),
            Self::Parquet => f.write_str("Parquet"),
            Self::Csv => f.write_str("Csv"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── SchemaChangeType ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaChangeType {
    FieldRemoved { field_name: String },
    FieldTypeChanged { field_name: String, from_type: String, to_type: String },
    NullabilityChanged { field_name: String, was_nullable: bool },
    FieldRenamed { old_name: String, new_name: String },
    Custom { description: String },
}

impl fmt::Display for SchemaChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FieldRemoved { field_name } => write!(f, "FieldRemoved({field_name})"),
            Self::FieldTypeChanged { field_name, from_type, to_type } => {
                write!(f, "FieldTypeChanged({field_name}: {from_type} -> {to_type})")
            }
            Self::NullabilityChanged { field_name, was_nullable } => {
                write!(f, "NullabilityChanged({field_name}, was_nullable={was_nullable})")
            }
            Self::FieldRenamed { old_name, new_name } => {
                write!(f, "FieldRenamed({old_name} -> {new_name})")
            }
            Self::Custom { description } => write!(f, "Custom({description})"),
        }
    }
}

// ── SchemaBreakingChange ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaBreakingChange {
    pub change_type: SchemaChangeType,
    pub severity: QualitySeverity,
    pub description: String,
}

// ── SchemaCompatibility ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaCompatibility {
    FullyCompatible,
    BackwardCompatible { notes: String },
    ForwardCompatible { notes: String },
    Breaking { breaking_changes: Vec<SchemaBreakingChange> },
    Unknown,
}

impl fmt::Display for SchemaCompatibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FullyCompatible => f.write_str("FullyCompatible"),
            Self::BackwardCompatible { notes } => write!(f, "BackwardCompatible({notes})"),
            Self::ForwardCompatible { notes } => write!(f, "ForwardCompatible({notes})"),
            Self::Breaking { breaking_changes } => {
                write!(f, "Breaking({} changes)", breaking_changes.len())
            }
            Self::Unknown => f.write_str("Unknown"),
        }
    }
}

// ── SchemaField ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaField {
    pub field_name: String,
    pub field_type: String,
    pub nullable: bool,
    pub description: Option<String>,
    pub sensitivity_label: Option<String>,
    pub constraints: Vec<String>,
}

// ── SchemaRecord ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SchemaRecord {
    pub schema_id: String,
    pub dataset_ref: String,
    pub version: String,
    pub fields: Vec<SchemaField>,
    pub format: SchemaFormat,
    pub registered_at: i64,
    pub registered_by: String,
    pub metadata: HashMap<String, String>,
}

// ── SchemaEvolutionPolicy ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SchemaEvolutionPolicy {
    pub policy_id: String,
    pub dataset_ref: String,
    pub allow_breaking_changes: bool,
    pub require_compatibility_check: bool,
    pub require_migration_plan: bool,
    pub require_deprecation_period: bool,
    pub deprecation_period_days: Option<String>,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_format_display() {
        let formats = vec![
            SchemaFormat::JsonSchema,
            SchemaFormat::Avro,
            SchemaFormat::Protobuf,
            SchemaFormat::Parquet,
            SchemaFormat::Csv,
            SchemaFormat::Custom { name: "Thrift".into() },
        ];
        for sf in &formats {
            assert!(!sf.to_string().is_empty());
        }
        assert_eq!(formats.len(), 6);
    }

    #[test]
    fn test_schema_change_type_display() {
        let changes = vec![
            SchemaChangeType::FieldRemoved { field_name: "old_col".into() },
            SchemaChangeType::FieldTypeChanged {
                field_name: "age".into(),
                from_type: "string".into(),
                to_type: "int64".into(),
            },
            SchemaChangeType::NullabilityChanged { field_name: "email".into(), was_nullable: true },
            SchemaChangeType::FieldRenamed { old_name: "fname".into(), new_name: "first_name".into() },
            SchemaChangeType::Custom { description: "added index".into() },
        ];
        for c in &changes {
            assert!(!c.to_string().is_empty());
        }
        assert_eq!(changes.len(), 5);
    }

    #[test]
    fn test_schema_compatibility_display() {
        let compat = vec![
            SchemaCompatibility::FullyCompatible,
            SchemaCompatibility::BackwardCompatible { notes: "new optional field".into() },
            SchemaCompatibility::ForwardCompatible { notes: "old readers ignore new field".into() },
            SchemaCompatibility::Breaking {
                breaking_changes: vec![SchemaBreakingChange {
                    change_type: SchemaChangeType::FieldRemoved { field_name: "x".into() },
                    severity: QualitySeverity::Critical,
                    description: "removed required field".into(),
                }],
            },
            SchemaCompatibility::Unknown,
        ];
        for c in &compat {
            assert!(!c.to_string().is_empty());
        }
        assert_eq!(compat.len(), 5);
    }

    #[test]
    fn test_schema_field_construction() {
        let field = SchemaField {
            field_name: "user_id".into(),
            field_type: "string".into(),
            nullable: false,
            description: Some("Unique user identifier".into()),
            sensitivity_label: Some("pii".into()),
            constraints: vec!["unique".into(), "not_null".into()],
        };
        assert_eq!(field.field_name, "user_id");
        assert!(!field.nullable);
        assert_eq!(field.constraints.len(), 2);
    }

    #[test]
    fn test_schema_field_minimal() {
        let field = SchemaField {
            field_name: "count".into(),
            field_type: "int64".into(),
            nullable: true,
            description: None,
            sensitivity_label: None,
            constraints: Vec::new(),
        };
        assert!(field.nullable);
        assert!(field.description.is_none());
        assert!(field.sensitivity_label.is_none());
    }

    #[test]
    fn test_schema_record_construction() {
        let record = SchemaRecord {
            schema_id: "sch-1".into(),
            dataset_ref: "ds-users".into(),
            version: "1.0.0".into(),
            fields: vec![
                SchemaField {
                    field_name: "id".into(),
                    field_type: "string".into(),
                    nullable: false,
                    description: None,
                    sensitivity_label: None,
                    constraints: vec!["primary_key".into()],
                },
                SchemaField {
                    field_name: "email".into(),
                    field_type: "string".into(),
                    nullable: true,
                    description: None,
                    sensitivity_label: Some("pii".into()),
                    constraints: Vec::new(),
                },
            ],
            format: SchemaFormat::JsonSchema,
            registered_at: 1000,
            registered_by: "schema-registry".into(),
            metadata: HashMap::new(),
        };
        assert_eq!(record.fields.len(), 2);
        assert_eq!(record.version, "1.0.0");
    }

    #[test]
    fn test_schema_evolution_policy_strict() {
        let policy = SchemaEvolutionPolicy {
            policy_id: "sep-1".into(),
            dataset_ref: "ds-users".into(),
            allow_breaking_changes: false,
            require_compatibility_check: true,
            require_migration_plan: true,
            require_deprecation_period: true,
            deprecation_period_days: Some("30".into()),
            created_at: 1000,
            metadata: HashMap::new(),
        };
        assert!(!policy.allow_breaking_changes);
        assert!(policy.require_migration_plan);
        assert_eq!(policy.deprecation_period_days, Some("30".into()));
    }

    #[test]
    fn test_schema_evolution_policy_relaxed() {
        let policy = SchemaEvolutionPolicy {
            policy_id: "sep-2".into(),
            dataset_ref: "ds-logs".into(),
            allow_breaking_changes: true,
            require_compatibility_check: false,
            require_migration_plan: false,
            require_deprecation_period: false,
            deprecation_period_days: None,
            created_at: 2000,
            metadata: HashMap::new(),
        };
        assert!(policy.allow_breaking_changes);
        assert!(policy.deprecation_period_days.is_none());
    }

    #[test]
    fn test_breaking_change_construction() {
        let change = SchemaBreakingChange {
            change_type: SchemaChangeType::FieldTypeChanged {
                field_name: "amount".into(),
                from_type: "string".into(),
                to_type: "float64".into(),
            },
            severity: QualitySeverity::Critical,
            description: "Type change breaks consumers".into(),
        };
        assert_eq!(change.severity, QualitySeverity::Critical);
        assert!(change.description.contains("consumers"));
    }

    #[test]
    fn test_breaking_compatibility_multiple_changes() {
        let compat = SchemaCompatibility::Breaking {
            breaking_changes: vec![
                SchemaBreakingChange {
                    change_type: SchemaChangeType::FieldRemoved { field_name: "a".into() },
                    severity: QualitySeverity::Critical,
                    description: "removed a".into(),
                },
                SchemaBreakingChange {
                    change_type: SchemaChangeType::FieldRemoved { field_name: "b".into() },
                    severity: QualitySeverity::Warning,
                    description: "removed b".into(),
                },
            ],
        };
        assert!(compat.to_string().contains("2 changes"));
    }
}
