// ═══════════════════════════════════════════════════════════════════════
// Export/Import — Secret serialization format interfaces.
//
// Layer 3 defines standardized serialization formats for secrets
// so they can be exported for backup, migration, or cross-system
// transfer in governed ways. RUNE provides the contract — the
// customer provides the encryption and transport.
// ═══════════════════════════════════════════════════════════════════════

use rune_lang::stdlib::crypto::hash::sha3_256_hex;
use serde::{Deserialize, Serialize};

use crate::error::SecretError;
use crate::secret::SecretEntry;

// ── SecretExporter trait ─────────────────────────────────────────

pub trait SecretExporter {
    fn export_secret(&self, entry: &SecretEntry) -> Result<Vec<u8>, SecretError>;
    fn export_batch(&self, entries: &[&SecretEntry]) -> Result<Vec<u8>, SecretError>;
    fn format_name(&self) -> &str;
    fn content_type(&self) -> &str;
}

// ── SecretImporter trait ─────────────────────────────────────────

pub trait SecretImporter {
    fn import_secret(&self, data: &[u8]) -> Result<SecretEntry, SecretError>;
    fn import_batch(&self, data: &[u8]) -> Result<Vec<SecretEntry>, SecretError>;
    fn format_name(&self) -> &str;
}

// ── JSON export metadata (excludes secret values by default) ─────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonSecretRecord {
    id: String,
    secret_type: String,
    classification: String,
    created_at: i64,
    updated_at: i64,
    expires_at: Option<i64>,
    created_by: String,
    description: String,
    tags: Vec<String>,
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value_base64: Option<String>,
}

impl JsonSecretRecord {
    fn from_entry(entry: &SecretEntry, include_values: bool) -> Self {
        let value_base64 = if include_values {
            Some(entry.value.expose_for(|bytes| {
                use serde::Serialize;
                // Use hex encoding for portability
                hex::encode(bytes)
            }))
        } else {
            None
        };
        Self {
            id: entry.id.as_str().to_string(),
            secret_type: format!("{:?}", entry.metadata.secret_type),
            classification: format!("{:?}", entry.metadata.classification),
            created_at: entry.metadata.created_at,
            updated_at: entry.metadata.updated_at,
            expires_at: entry.metadata.expires_at,
            created_by: entry.metadata.created_by.clone(),
            description: entry.metadata.description.clone(),
            tags: entry.metadata.tags.clone(),
            state: format!("{:?}", entry.state),
            value_base64,
        }
    }
}

// ── JsonSecretExporter ───────────────────────────────────────────

pub struct JsonSecretExporter {
    include_values: bool,
}

impl JsonSecretExporter {
    pub fn new() -> Self {
        Self {
            include_values: false,
        }
    }

    pub fn with_include_values(mut self, include: bool) -> Self {
        self.include_values = include;
        self
    }
}

impl Default for JsonSecretExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretExporter for JsonSecretExporter {
    fn export_secret(&self, entry: &SecretEntry) -> Result<Vec<u8>, SecretError> {
        let record = JsonSecretRecord::from_entry(entry, self.include_values);
        serde_json::to_vec_pretty(&record)
            .map_err(|e| SecretError::EncryptionFailed(format!("JSON export: {e}")))
    }

    fn export_batch(&self, entries: &[&SecretEntry]) -> Result<Vec<u8>, SecretError> {
        let records: Vec<JsonSecretRecord> = entries
            .iter()
            .map(|e| JsonSecretRecord::from_entry(e, self.include_values))
            .collect();
        serde_json::to_vec_pretty(&records)
            .map_err(|e| SecretError::EncryptionFailed(format!("JSON batch export: {e}")))
    }

    fn format_name(&self) -> &str {
        "json"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ── JsonSecretImporter ───────────────────────────────────────────

pub struct JsonSecretImporter;

impl JsonSecretImporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for JsonSecretImporter {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretImporter for JsonSecretImporter {
    fn import_secret(&self, data: &[u8]) -> Result<SecretEntry, SecretError> {
        let record: JsonSecretRecord = serde_json::from_slice(data)
            .map_err(|e| SecretError::EncryptionFailed(format!("JSON import: {e}")))?;
        Ok(record_to_entry(&record))
    }

    fn import_batch(&self, data: &[u8]) -> Result<Vec<SecretEntry>, SecretError> {
        let records: Vec<JsonSecretRecord> = serde_json::from_slice(data)
            .map_err(|e| SecretError::EncryptionFailed(format!("JSON batch import: {e}")))?;
        Ok(records.iter().map(record_to_entry).collect())
    }

    fn format_name(&self) -> &str {
        "json"
    }
}

fn parse_secret_type(s: &str) -> crate::secret::SecretType {
    match s {
        "ApiKey" => crate::secret::SecretType::ApiKey,
        "Password" => crate::secret::SecretType::Password,
        "Token" => crate::secret::SecretType::Token,
        "Certificate" => crate::secret::SecretType::Certificate,
        "PrivateKey" => crate::secret::SecretType::PrivateKey,
        "SymmetricKey" => crate::secret::SecretType::SymmetricKey,
        "SeedPhrase" => crate::secret::SecretType::SeedPhrase,
        "ConnectionString" => crate::secret::SecretType::ConnectionString,
        "Webhook" => crate::secret::SecretType::Webhook,
        "OAuthSecret" => crate::secret::SecretType::OAuthSecret,
        other => crate::secret::SecretType::Custom(other.to_string()),
    }
}

fn parse_classification(s: &str) -> rune_permissions::ClassificationLevel {
    match s {
        "Public" => rune_permissions::ClassificationLevel::Public,
        "Internal" => rune_permissions::ClassificationLevel::Internal,
        "Confidential" => rune_permissions::ClassificationLevel::Confidential,
        "Restricted" => rune_permissions::ClassificationLevel::Restricted,
        "TopSecret" => rune_permissions::ClassificationLevel::TopSecret,
        _ => rune_permissions::ClassificationLevel::Internal,
    }
}

fn parse_state(s: &str) -> crate::secret::SecretState {
    match s {
        "Active" => crate::secret::SecretState::Active,
        "Rotated" => crate::secret::SecretState::Rotated,
        "Expired" => crate::secret::SecretState::Expired,
        "Compromised" => crate::secret::SecretState::Compromised,
        "Destroyed" => crate::secret::SecretState::Destroyed,
        _ => crate::secret::SecretState::Active,
    }
}

fn record_to_entry(record: &JsonSecretRecord) -> SecretEntry {
    use crate::secret::*;

    let value = if let Some(ref hex_val) = record.value_base64 {
        let bytes = hex::decode(hex_val).unwrap_or_default();
        SecretValue::new(bytes)
    } else {
        SecretValue::new(vec![])
    };

    let mut meta = SecretMetadata::new(
        parse_secret_type(&record.secret_type),
        parse_classification(&record.classification),
        &record.created_by,
    )
    .with_description(&record.description)
    .with_timestamps(record.created_at, record.updated_at)
    .with_tags(record.tags.clone());

    if let Some(exp) = record.expires_at {
        meta = meta.with_expires_at(exp);
    }

    let mut entry = SecretEntry::new(SecretId::new(&record.id), value, meta);
    entry.state = parse_state(&record.state);
    entry
}

// ── EnvelopeFormat ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeFormat {
    pub format_version: String,
    pub key_id: String,
    pub algorithm: String,
    pub payload_placeholder: Vec<u8>,
    pub integrity_hash: String,
    pub timestamp: i64,
}

// ── EnvelopeExporter ─────────────────────────────────────────────

pub struct EnvelopeExporter {
    key_id: String,
    algorithm: String,
}

impl EnvelopeExporter {
    pub fn new(key_id: &str, algorithm: &str) -> Self {
        Self {
            key_id: key_id.to_string(),
            algorithm: algorithm.to_string(),
        }
    }
}

impl SecretExporter for EnvelopeExporter {
    fn export_secret(&self, entry: &SecretEntry) -> Result<Vec<u8>, SecretError> {
        let payload = entry.value.expose_for(|bytes| bytes.to_vec());
        let integrity_hash = sha3_256_hex(&payload);
        let envelope = EnvelopeFormat {
            format_version: "1.0".to_string(),
            key_id: self.key_id.clone(),
            algorithm: self.algorithm.clone(),
            payload_placeholder: payload,
            integrity_hash,
            timestamp: entry.metadata.created_at,
        };
        serde_json::to_vec_pretty(&envelope)
            .map_err(|e| SecretError::EncryptionFailed(format!("envelope export: {e}")))
    }

    fn export_batch(&self, entries: &[&SecretEntry]) -> Result<Vec<u8>, SecretError> {
        let envelopes: Vec<EnvelopeFormat> = entries
            .iter()
            .map(|entry| {
                let payload = entry.value.expose_for(|bytes| bytes.to_vec());
                let integrity_hash = sha3_256_hex(&payload);
                EnvelopeFormat {
                    format_version: "1.0".to_string(),
                    key_id: self.key_id.clone(),
                    algorithm: self.algorithm.clone(),
                    payload_placeholder: payload,
                    integrity_hash,
                    timestamp: entry.metadata.created_at,
                }
            })
            .collect();
        serde_json::to_vec_pretty(&envelopes)
            .map_err(|e| SecretError::EncryptionFailed(format!("envelope batch export: {e}")))
    }

    fn format_name(&self) -> &str {
        "envelope"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::*;
    use rune_permissions::ClassificationLevel;

    fn make_entry(id: &str) -> SecretEntry {
        SecretEntry::new(
            SecretId::new(id),
            SecretValue::from_str("my-secret-value"),
            SecretMetadata::new(SecretType::ApiKey, ClassificationLevel::Internal, "admin")
                .with_timestamps(100, 200)
                .with_description("test key")
                .with_tags(vec!["prod".to_string()]),
        )
    }

    #[test]
    fn test_json_exporter_produces_valid_json() {
        let exporter = JsonSecretExporter::new();
        let entry = make_entry("k1");
        let data = exporter.export_secret(&entry).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(parsed["id"], "k1");
        assert_eq!(parsed["secret_type"], "ApiKey");
    }

    #[test]
    fn test_json_exporter_excludes_values_by_default() {
        let exporter = JsonSecretExporter::new();
        let entry = make_entry("k1");
        let data = exporter.export_secret(&entry).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert!(parsed.get("value_base64").is_none());
    }

    #[test]
    fn test_json_exporter_with_include_values() {
        let exporter = JsonSecretExporter::new().with_include_values(true);
        let entry = make_entry("k1");
        let data = exporter.export_secret(&entry).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert!(parsed.get("value_base64").is_some());
    }

    #[test]
    fn test_json_importer_roundtrips() {
        let exporter = JsonSecretExporter::new().with_include_values(true);
        let entry = make_entry("k1");
        let data = exporter.export_secret(&entry).unwrap();
        let importer = JsonSecretImporter::new();
        let imported = importer.import_secret(&data).unwrap();
        assert_eq!(imported.id.as_str(), "k1");
        imported
            .value
            .expose_for(|bytes| assert_eq!(bytes, b"my-secret-value"));
    }

    #[test]
    fn test_json_batch_roundtrip() {
        let exporter = JsonSecretExporter::new().with_include_values(true);
        let e1 = make_entry("k1");
        let e2 = make_entry("k2");
        let data = exporter.export_batch(&[&e1, &e2]).unwrap();
        let importer = JsonSecretImporter::new();
        let imported = importer.import_batch(&data).unwrap();
        assert_eq!(imported.len(), 2);
    }

    #[test]
    fn test_envelope_exporter_produces_envelope() {
        let exporter = EnvelopeExporter::new("master-key-1", "AES-256-GCM");
        let entry = make_entry("k1");
        let data = exporter.export_secret(&entry).unwrap();
        let envelope: EnvelopeFormat = serde_json::from_slice(&data).unwrap();
        assert_eq!(envelope.format_version, "1.0");
        assert_eq!(envelope.key_id, "master-key-1");
        assert_eq!(envelope.algorithm, "AES-256-GCM");
        assert!(!envelope.payload_placeholder.is_empty());
    }

    #[test]
    fn test_envelope_integrity_hash_is_sha3() {
        let exporter = EnvelopeExporter::new("k1", "ChaCha20");
        let entry = make_entry("k1");
        let data = exporter.export_secret(&entry).unwrap();
        let envelope: EnvelopeFormat = serde_json::from_slice(&data).unwrap();
        // SHA3-256 produces 64 hex characters
        assert_eq!(envelope.integrity_hash.len(), 64);
        // Verify it matches
        let expected = sha3_256_hex(&envelope.payload_placeholder);
        assert_eq!(envelope.integrity_hash, expected);
    }

    #[test]
    fn test_envelope_format_fields_populated() {
        let exporter = EnvelopeExporter::new("kms-key-42", "RSA-OAEP");
        let entry = make_entry("s1");
        let data = exporter.export_secret(&entry).unwrap();
        let envelope: EnvelopeFormat = serde_json::from_slice(&data).unwrap();
        assert_eq!(envelope.key_id, "kms-key-42");
        assert_eq!(envelope.algorithm, "RSA-OAEP");
        assert_eq!(envelope.timestamp, 100);
    }
}
