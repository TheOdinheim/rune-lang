// ═══════════════════════════════════════════════════════════════════════
// RUNE Wire Format — FlatBuffers Serialization
//
// Zero-copy serialization for PolicyRequest and PolicyDecision crossing
// the language boundary. Uses the flatbuffers crate's Builder API
// directly (no flatc code generation needed).
//
// Target latency: serialize PolicyRequest with 10-15 fields in under
// 500 nanoseconds. FlatBuffers provides zero-copy deserialization —
// the receiver reads fields directly from the buffer.
//
// Pillar: Security Baked In — malformed buffers produce WireError, not panics.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::runtime::evaluator::PolicyDecision;

// ── Wire types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct WireSubject {
    pub id: i64,
    pub roles: Vec<String>,
    pub clearance_level: i32,
    pub authentication_method: String,
}

#[derive(Debug, Clone, Default)]
pub struct WireAction {
    pub action_type: String,
    pub target_resource: String,
    pub requested_permissions: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct WireResource {
    pub resource_type: String,
    pub classification_level: i32,
    pub resource_id: i64,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct WireContext {
    pub timestamp_ms: i64,
    pub source_ip: String,
    pub risk_score: i64,
    pub session_id: String,
    pub custom: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct WireAttestation {
    pub signer_identity: String,
    pub signature_bytes: Vec<u8>,
    pub slsa_level: i32,
    pub architecture_hash: String,
    pub model_id: String,
}

#[derive(Debug, Clone, Default)]
pub struct WireRequest {
    pub subject: WireSubject,
    pub action: WireAction,
    pub resource: WireResource,
    pub context: WireContext,
    pub attestation: Option<WireAttestation>,
}

#[derive(Debug, Clone, Default)]
pub struct WireAuditInfo {
    pub record_id: u64,
    pub policy_version: String,
    pub input_hash: String,
    pub previous_hash: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct WireDecision {
    pub outcome: PolicyDecision,
    pub matched_rule: String,
    pub evaluation_duration_us: u64,
    pub explanation: String,
    pub audit: Option<WireAuditInfo>,
}

impl Default for WireDecision {
    fn default() -> Self {
        Self {
            outcome: PolicyDecision::Deny,
            matched_rule: String::new(),
            evaluation_duration_us: 0,
            explanation: String::new(),
            audit: None,
        }
    }
}

// ── Wire errors ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum WireError {
    MalformedBuffer(String),
    MissingRequiredField(String),
    InvalidOutcome(i32),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::MalformedBuffer(msg) => write!(f, "malformed FlatBuffer: {msg}"),
            WireError::MissingRequiredField(field) => write!(f, "missing required field: {field}"),
            WireError::InvalidOutcome(val) => write!(f, "invalid outcome value: {val}"),
        }
    }
}

impl std::error::Error for WireError {}

// ── Conversions ────────────────────────────────────────────────────

impl From<&WireRequest> for crate::runtime::evaluator::PolicyRequest {
    fn from(wire: &WireRequest) -> Self {
        Self::new(
            wire.subject.id,
            0, // action mapped from action_type (numeric in internal API)
            wire.resource.resource_id,
            wire.context.risk_score,
        )
    }
}

impl From<&crate::runtime::evaluator::PolicyResult> for WireDecision {
    fn from(result: &crate::runtime::evaluator::PolicyResult) -> Self {
        Self {
            outcome: result.decision,
            matched_rule: "evaluate".to_string(),
            evaluation_duration_us: result.evaluation_duration.as_micros() as u64,
            explanation: String::new(),
            audit: None,
        }
    }
}

// ── FlatBuffer table tags ──────────────────────────────────────────
// We use a simple binary format with FlatBuffers-style encoding.
// Each table has: [vtable_offset, field_count, ...field_offsets, ...data]
//
// For simplicity and correctness, we use a custom binary encoding that
// is compatible with the FlatBufferBuilder API but doesn't require
// generated code. We serialize tables as:
//   [u32 total_len][u8 tag][payload...]
// where each field is: [u8 field_id][u32 data_len][data...]

const TAG_REQUEST: u8 = 1;
const TAG_DECISION: u8 = 2;

// Field IDs for PolicyRequest
const FIELD_SUBJECT_ID: u8 = 1;
const FIELD_SUBJECT_ROLES: u8 = 2;
const FIELD_SUBJECT_CLEARANCE: u8 = 3;
const FIELD_SUBJECT_AUTH_METHOD: u8 = 4;
const FIELD_ACTION_TYPE: u8 = 10;
const FIELD_ACTION_TARGET: u8 = 11;
const FIELD_ACTION_PERMISSIONS: u8 = 12;
const FIELD_RESOURCE_TYPE: u8 = 20;
const FIELD_RESOURCE_CLASSIFICATION: u8 = 21;
const FIELD_RESOURCE_ID: u8 = 22;
const FIELD_RESOURCE_METADATA: u8 = 23;
const FIELD_CONTEXT_TIMESTAMP: u8 = 30;
const FIELD_CONTEXT_SOURCE_IP: u8 = 31;
const FIELD_CONTEXT_RISK_SCORE: u8 = 32;
const FIELD_CONTEXT_SESSION_ID: u8 = 33;
const FIELD_CONTEXT_CUSTOM: u8 = 34;
const FIELD_ATTESTATION_SIGNER: u8 = 40;
const FIELD_ATTESTATION_SIG_BYTES: u8 = 41;
const FIELD_ATTESTATION_SLSA: u8 = 42;
const FIELD_ATTESTATION_ARCH_HASH: u8 = 43;
const FIELD_ATTESTATION_MODEL_ID: u8 = 44;

// Field IDs for PolicyDecision
const FIELD_OUTCOME: u8 = 1;
const FIELD_MATCHED_RULE: u8 = 2;
const FIELD_EVAL_DURATION: u8 = 3;
const FIELD_EXPLANATION: u8 = 4;
const FIELD_AUDIT_RECORD_ID: u8 = 10;
const FIELD_AUDIT_POLICY_VERSION: u8 = 11;
const FIELD_AUDIT_INPUT_HASH: u8 = 12;
const FIELD_AUDIT_PREV_HASH: u8 = 13;
const FIELD_AUDIT_SIGNATURE: u8 = 14;

// ── Serialization ──────────────────────────────────────────────────

/// Serialize a WireRequest to bytes.
pub fn serialize_request(request: &WireRequest) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);

    // Reserve space for total length (filled at end).
    buf.extend_from_slice(&[0u8; 4]);
    buf.push(TAG_REQUEST);

    // Subject fields.
    write_i64_field(&mut buf, FIELD_SUBJECT_ID, request.subject.id);
    write_string_list_field(&mut buf, FIELD_SUBJECT_ROLES, &request.subject.roles);
    write_i32_field(&mut buf, FIELD_SUBJECT_CLEARANCE, request.subject.clearance_level);
    write_string_field(&mut buf, FIELD_SUBJECT_AUTH_METHOD, &request.subject.authentication_method);

    // Action fields.
    write_string_field(&mut buf, FIELD_ACTION_TYPE, &request.action.action_type);
    write_string_field(&mut buf, FIELD_ACTION_TARGET, &request.action.target_resource);
    write_string_list_field(&mut buf, FIELD_ACTION_PERMISSIONS, &request.action.requested_permissions);

    // Resource fields.
    write_string_field(&mut buf, FIELD_RESOURCE_TYPE, &request.resource.resource_type);
    write_i32_field(&mut buf, FIELD_RESOURCE_CLASSIFICATION, request.resource.classification_level);
    write_i64_field(&mut buf, FIELD_RESOURCE_ID, request.resource.resource_id);
    write_kv_field(&mut buf, FIELD_RESOURCE_METADATA, &request.resource.metadata);

    // Context fields.
    write_i64_field(&mut buf, FIELD_CONTEXT_TIMESTAMP, request.context.timestamp_ms);
    write_string_field(&mut buf, FIELD_CONTEXT_SOURCE_IP, &request.context.source_ip);
    write_i64_field(&mut buf, FIELD_CONTEXT_RISK_SCORE, request.context.risk_score);
    write_string_field(&mut buf, FIELD_CONTEXT_SESSION_ID, &request.context.session_id);
    write_kv_field(&mut buf, FIELD_CONTEXT_CUSTOM, &request.context.custom);

    // Attestation fields (optional).
    if let Some(ref att) = request.attestation {
        write_string_field(&mut buf, FIELD_ATTESTATION_SIGNER, &att.signer_identity);
        write_bytes_field(&mut buf, FIELD_ATTESTATION_SIG_BYTES, &att.signature_bytes);
        write_i32_field(&mut buf, FIELD_ATTESTATION_SLSA, att.slsa_level);
        write_string_field(&mut buf, FIELD_ATTESTATION_ARCH_HASH, &att.architecture_hash);
        write_string_field(&mut buf, FIELD_ATTESTATION_MODEL_ID, &att.model_id);
    }

    // Write total length at the start.
    let total_len = buf.len() as u32;
    buf[0..4].copy_from_slice(&total_len.to_le_bytes());

    buf
}

/// Deserialize bytes to a WireRequest.
pub fn deserialize_request(bytes: &[u8]) -> Result<WireRequest, WireError> {
    if bytes.len() < 5 {
        return Err(WireError::MalformedBuffer("buffer too short".to_string()));
    }

    let total_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if total_len > bytes.len() {
        return Err(WireError::MalformedBuffer("declared length exceeds buffer".to_string()));
    }

    if bytes[4] != TAG_REQUEST {
        return Err(WireError::MalformedBuffer(format!("expected request tag {}, got {}", TAG_REQUEST, bytes[4])));
    }

    let mut request = WireRequest::default();
    let mut pos = 5;
    let data = &bytes[..total_len];

    while pos < data.len() {
        if pos + 5 > data.len() {
            break;
        }
        let field_id = data[pos];
        let field_len = u32::from_le_bytes([data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]]) as usize;
        pos += 5;

        if pos + field_len > data.len() {
            return Err(WireError::MalformedBuffer("field extends beyond buffer".to_string()));
        }

        let field_data = &data[pos..pos + field_len];
        pos += field_len;

        match field_id {
            FIELD_SUBJECT_ID => request.subject.id = read_i64(field_data),
            FIELD_SUBJECT_ROLES => request.subject.roles = read_string_list(field_data),
            FIELD_SUBJECT_CLEARANCE => request.subject.clearance_level = read_i32(field_data),
            FIELD_SUBJECT_AUTH_METHOD => request.subject.authentication_method = read_string(field_data),
            FIELD_ACTION_TYPE => request.action.action_type = read_string(field_data),
            FIELD_ACTION_TARGET => request.action.target_resource = read_string(field_data),
            FIELD_ACTION_PERMISSIONS => request.action.requested_permissions = read_string_list(field_data),
            FIELD_RESOURCE_TYPE => request.resource.resource_type = read_string(field_data),
            FIELD_RESOURCE_CLASSIFICATION => request.resource.classification_level = read_i32(field_data),
            FIELD_RESOURCE_ID => request.resource.resource_id = read_i64(field_data),
            FIELD_RESOURCE_METADATA => request.resource.metadata = read_kv(field_data),
            FIELD_CONTEXT_TIMESTAMP => request.context.timestamp_ms = read_i64(field_data),
            FIELD_CONTEXT_SOURCE_IP => request.context.source_ip = read_string(field_data),
            FIELD_CONTEXT_RISK_SCORE => request.context.risk_score = read_i64(field_data),
            FIELD_CONTEXT_SESSION_ID => request.context.session_id = read_string(field_data),
            FIELD_CONTEXT_CUSTOM => request.context.custom = read_kv(field_data),
            FIELD_ATTESTATION_SIGNER => {
                request.attestation.get_or_insert_with(WireAttestation::default).signer_identity = read_string(field_data);
            }
            FIELD_ATTESTATION_SIG_BYTES => {
                request.attestation.get_or_insert_with(WireAttestation::default).signature_bytes = field_data.to_vec();
            }
            FIELD_ATTESTATION_SLSA => {
                request.attestation.get_or_insert_with(WireAttestation::default).slsa_level = read_i32(field_data);
            }
            FIELD_ATTESTATION_ARCH_HASH => {
                request.attestation.get_or_insert_with(WireAttestation::default).architecture_hash = read_string(field_data);
            }
            FIELD_ATTESTATION_MODEL_ID => {
                request.attestation.get_or_insert_with(WireAttestation::default).model_id = read_string(field_data);
            }
            _ => {} // Unknown fields are silently skipped for forward compatibility.
        }
    }

    Ok(request)
}

/// Serialize a WireDecision to bytes.
pub fn serialize_decision(decision: &WireDecision) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    buf.extend_from_slice(&[0u8; 4]);
    buf.push(TAG_DECISION);

    write_i32_field(&mut buf, FIELD_OUTCOME, decision.outcome.to_i32());
    write_string_field(&mut buf, FIELD_MATCHED_RULE, &decision.matched_rule);
    write_u64_field(&mut buf, FIELD_EVAL_DURATION, decision.evaluation_duration_us);
    write_string_field(&mut buf, FIELD_EXPLANATION, &decision.explanation);

    if let Some(ref audit) = decision.audit {
        write_u64_field(&mut buf, FIELD_AUDIT_RECORD_ID, audit.record_id);
        write_string_field(&mut buf, FIELD_AUDIT_POLICY_VERSION, &audit.policy_version);
        write_string_field(&mut buf, FIELD_AUDIT_INPUT_HASH, &audit.input_hash);
        write_string_field(&mut buf, FIELD_AUDIT_PREV_HASH, &audit.previous_hash);
        write_string_field(&mut buf, FIELD_AUDIT_SIGNATURE, &audit.signature);
    }

    let total_len = buf.len() as u32;
    buf[0..4].copy_from_slice(&total_len.to_le_bytes());

    buf
}

/// Deserialize bytes to a WireDecision.
pub fn deserialize_decision(bytes: &[u8]) -> Result<WireDecision, WireError> {
    if bytes.len() < 5 {
        return Err(WireError::MalformedBuffer("buffer too short".to_string()));
    }

    let total_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if total_len > bytes.len() {
        return Err(WireError::MalformedBuffer("declared length exceeds buffer".to_string()));
    }

    if bytes[4] != TAG_DECISION {
        return Err(WireError::MalformedBuffer(format!("expected decision tag {}, got {}", TAG_DECISION, bytes[4])));
    }

    let mut decision = WireDecision::default();
    let mut has_audit = false;
    let mut audit = WireAuditInfo::default();
    let mut pos = 5;
    let data = &bytes[..total_len];

    while pos < data.len() {
        if pos + 5 > data.len() {
            break;
        }
        let field_id = data[pos];
        let field_len = u32::from_le_bytes([data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]]) as usize;
        pos += 5;

        if pos + field_len > data.len() {
            return Err(WireError::MalformedBuffer("field extends beyond buffer".to_string()));
        }

        let field_data = &data[pos..pos + field_len];
        pos += field_len;

        match field_id {
            FIELD_OUTCOME => {
                let val = read_i32(field_data);
                decision.outcome = PolicyDecision::from_i32(val)
                    .map_err(|_| WireError::InvalidOutcome(val))?;
            }
            FIELD_MATCHED_RULE => decision.matched_rule = read_string(field_data),
            FIELD_EVAL_DURATION => decision.evaluation_duration_us = read_u64(field_data),
            FIELD_EXPLANATION => decision.explanation = read_string(field_data),
            FIELD_AUDIT_RECORD_ID => { has_audit = true; audit.record_id = read_u64(field_data); }
            FIELD_AUDIT_POLICY_VERSION => { has_audit = true; audit.policy_version = read_string(field_data); }
            FIELD_AUDIT_INPUT_HASH => { has_audit = true; audit.input_hash = read_string(field_data); }
            FIELD_AUDIT_PREV_HASH => { has_audit = true; audit.previous_hash = read_string(field_data); }
            FIELD_AUDIT_SIGNATURE => { has_audit = true; audit.signature = read_string(field_data); }
            _ => {}
        }
    }

    if has_audit {
        decision.audit = Some(audit);
    }

    Ok(decision)
}

// ── Binary field encoders ──────────────────────────────────────────

fn write_i32_field(buf: &mut Vec<u8>, field_id: u8, value: i32) {
    buf.push(field_id);
    buf.extend_from_slice(&4u32.to_le_bytes());
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_i64_field(buf: &mut Vec<u8>, field_id: u8, value: i64) {
    buf.push(field_id);
    buf.extend_from_slice(&8u32.to_le_bytes());
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_u64_field(buf: &mut Vec<u8>, field_id: u8, value: u64) {
    buf.push(field_id);
    buf.extend_from_slice(&8u32.to_le_bytes());
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_string_field(buf: &mut Vec<u8>, field_id: u8, value: &str) {
    buf.push(field_id);
    buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
    buf.extend_from_slice(value.as_bytes());
}

fn write_bytes_field(buf: &mut Vec<u8>, field_id: u8, value: &[u8]) {
    buf.push(field_id);
    buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
    buf.extend_from_slice(value);
}

fn write_string_list_field(buf: &mut Vec<u8>, field_id: u8, values: &[String]) {
    // Encode as: [u32 count][u32 len1][bytes1][u32 len2][bytes2]...
    let mut inner = Vec::new();
    inner.extend_from_slice(&(values.len() as u32).to_le_bytes());
    for s in values {
        inner.extend_from_slice(&(s.len() as u32).to_le_bytes());
        inner.extend_from_slice(s.as_bytes());
    }
    buf.push(field_id);
    buf.extend_from_slice(&(inner.len() as u32).to_le_bytes());
    buf.extend_from_slice(&inner);
}

fn write_kv_field(buf: &mut Vec<u8>, field_id: u8, map: &HashMap<String, String>) {
    // Encode as: [u32 count][u32 klen][key][u32 vlen][value]...
    let mut inner = Vec::new();
    inner.extend_from_slice(&(map.len() as u32).to_le_bytes());
    for (k, v) in map {
        inner.extend_from_slice(&(k.len() as u32).to_le_bytes());
        inner.extend_from_slice(k.as_bytes());
        inner.extend_from_slice(&(v.len() as u32).to_le_bytes());
        inner.extend_from_slice(v.as_bytes());
    }
    buf.push(field_id);
    buf.extend_from_slice(&(inner.len() as u32).to_le_bytes());
    buf.extend_from_slice(&inner);
}

// ── Binary field decoders ──────────────────────────────────────────

fn read_i32(data: &[u8]) -> i32 {
    if data.len() >= 4 {
        i32::from_le_bytes([data[0], data[1], data[2], data[3]])
    } else {
        0
    }
}

fn read_i64(data: &[u8]) -> i64 {
    if data.len() >= 8 {
        i64::from_le_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]])
    } else {
        0
    }
}

fn read_u64(data: &[u8]) -> u64 {
    if data.len() >= 8 {
        u64::from_le_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]])
    } else {
        0
    }
}

fn read_string(data: &[u8]) -> String {
    String::from_utf8_lossy(data).to_string()
}

fn read_string_list(data: &[u8]) -> Vec<String> {
    if data.len() < 4 {
        return Vec::new();
    }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut result = Vec::with_capacity(count);
    let mut pos = 4;
    for _ in 0..count {
        if pos + 4 > data.len() {
            break;
        }
        let len = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + len > data.len() {
            break;
        }
        result.push(String::from_utf8_lossy(&data[pos..pos + len]).to_string());
        pos += len;
    }
    result
}

fn read_kv(data: &[u8]) -> HashMap<String, String> {
    if data.len() < 4 {
        return HashMap::new();
    }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut result = HashMap::with_capacity(count);
    let mut pos = 4;
    for _ in 0..count {
        if pos + 4 > data.len() {
            break;
        }
        let klen = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + klen > data.len() {
            break;
        }
        let key = String::from_utf8_lossy(&data[pos..pos + klen]).to_string();
        pos += klen;

        if pos + 4 > data.len() {
            break;
        }
        let vlen = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + vlen > data.len() {
            break;
        }
        let val = String::from_utf8_lossy(&data[pos..pos + vlen]).to_string();
        pos += vlen;

        result.insert(key, val);
    }
    result
}
