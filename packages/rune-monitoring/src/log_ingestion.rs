// ═══════════════════════════════════════════════════════════════════════
// Structured Log Ingestor — Parses and ingests structured log lines
// from multiple formats into a common ECS-shaped representation.
//
// StructuredLogRecord follows the Elastic Common Schema (ECS) shape:
// timestamp, severity, service_name, message, plus key-value fields.
// The ingestor trait supports batch ingestion and format-aware parsing.
//
// Reference implementations: LogfmtIngestor, SyslogRfc5424Ingestor,
// JsonLinesIngestor, NullLogIngestor.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::MonitoringError;

// ── LogLineFormat ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LogLineFormat {
    EcsJson,
    LogfmtLine,
    SyslogRfc5424,
    CommonLogFormat,
    JsonLines,
    OtelLogRecord,
}

impl fmt::Display for LogLineFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EcsJson => write!(f, "ECS-JSON"),
            Self::LogfmtLine => write!(f, "logfmt"),
            Self::SyslogRfc5424 => write!(f, "syslog-rfc5424"),
            Self::CommonLogFormat => write!(f, "common-log-format"),
            Self::JsonLines => write!(f, "json-lines"),
            Self::OtelLogRecord => write!(f, "otel-log-record"),
        }
    }
}

// ── StructuredLogRecord ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredLogRecord {
    pub timestamp: i64,
    pub severity: String,
    pub service_name: String,
    pub message: String,
    pub fields: HashMap<String, String>,
    pub source_format: LogLineFormat,
}

impl StructuredLogRecord {
    pub fn new(timestamp: i64, severity: &str, service_name: &str, message: &str, source_format: LogLineFormat) -> Self {
        Self {
            timestamp,
            severity: severity.to_string(),
            service_name: service_name.to_string(),
            message: message.to_string(),
            fields: HashMap::new(),
            source_format,
        }
    }

    pub fn with_field(mut self, key: &str, value: &str) -> Self {
        self.fields.insert(key.to_string(), value.to_string());
        self
    }
}

// ── IngestResult ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestResult {
    pub ingested_count: usize,
    pub failed_count: usize,
    pub errors: Vec<String>,
}

impl IngestResult {
    pub fn success(count: usize) -> Self {
        Self { ingested_count: count, failed_count: 0, errors: Vec::new() }
    }

    pub fn partial(ingested: usize, failed: usize, errors: Vec<String>) -> Self {
        Self { ingested_count: ingested, failed_count: failed, errors }
    }
}

// ── StructuredLogIngestor trait ─────────────────────────────────

pub trait StructuredLogIngestor {
    fn ingest_log(&mut self, record: StructuredLogRecord) -> Result<(), MonitoringError>;
    fn ingest_batch(&mut self, records: Vec<StructuredLogRecord>) -> IngestResult;
    fn parse_log_line(&self, line: &str) -> Result<StructuredLogRecord, MonitoringError>;
    fn supported_formats(&self) -> Vec<LogLineFormat>;
    fn ingestor_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── LogfmtIngestor ──────────────────────────────────────────────

pub struct LogfmtIngestor {
    id: String,
    records: Vec<StructuredLogRecord>,
}

impl LogfmtIngestor {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string(), records: Vec::new() }
    }

    pub fn records(&self) -> &[StructuredLogRecord] {
        &self.records
    }
}

impl StructuredLogIngestor for LogfmtIngestor {
    fn ingest_log(&mut self, record: StructuredLogRecord) -> Result<(), MonitoringError> {
        self.records.push(record);
        Ok(())
    }

    fn ingest_batch(&mut self, records: Vec<StructuredLogRecord>) -> IngestResult {
        let count = records.len();
        self.records.extend(records);
        IngestResult::success(count)
    }

    fn parse_log_line(&self, line: &str) -> Result<StructuredLogRecord, MonitoringError> {
        // logfmt: key=value key="quoted value" ...
        let mut fields = HashMap::new();
        let mut chars = line.chars().peekable();
        while chars.peek().is_some() {
            // skip whitespace
            while chars.peek() == Some(&' ') { chars.next(); }
            // read key
            let mut key = String::new();
            while let Some(&c) = chars.peek() {
                if c == '=' { break; }
                key.push(c);
                chars.next();
            }
            if key.is_empty() { break; }
            chars.next(); // skip '='
            // read value (may be quoted)
            let mut val = String::new();
            if chars.peek() == Some(&'"') {
                chars.next(); // skip opening quote
                while let Some(&c) = chars.peek() {
                    if c == '"' { chars.next(); break; }
                    val.push(c);
                    chars.next();
                }
            } else {
                while let Some(&c) = chars.peek() {
                    if c == ' ' { break; }
                    val.push(c);
                    chars.next();
                }
            }
            fields.insert(key, val);
        }
        let timestamp: i64 = fields.get("ts").or(fields.get("time"))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let severity = fields.remove("level").unwrap_or_else(|| "info".to_string());
        let message = fields.remove("msg").unwrap_or_default();
        let service_name = fields.remove("service").unwrap_or_else(|| "unknown".to_string());
        Ok(StructuredLogRecord {
            timestamp,
            severity,
            service_name,
            message,
            fields,
            source_format: LogLineFormat::LogfmtLine,
        })
    }

    fn supported_formats(&self) -> Vec<LogLineFormat> {
        vec![LogLineFormat::LogfmtLine]
    }

    fn ingestor_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── SyslogRfc5424Ingestor ───────────────────────────────────────

pub struct SyslogRfc5424Ingestor {
    id: String,
    records: Vec<StructuredLogRecord>,
}

impl SyslogRfc5424Ingestor {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string(), records: Vec::new() }
    }

    pub fn records(&self) -> &[StructuredLogRecord] {
        &self.records
    }
}

impl StructuredLogIngestor for SyslogRfc5424Ingestor {
    fn ingest_log(&mut self, record: StructuredLogRecord) -> Result<(), MonitoringError> {
        self.records.push(record);
        Ok(())
    }

    fn ingest_batch(&mut self, records: Vec<StructuredLogRecord>) -> IngestResult {
        let count = records.len();
        self.records.extend(records);
        IngestResult::success(count)
    }

    fn parse_log_line(&self, line: &str) -> Result<StructuredLogRecord, MonitoringError> {
        // Simplified RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
        let parts: Vec<&str> = line.splitn(7, ' ').collect();
        if parts.len() < 7 {
            return Err(MonitoringError::InvalidConfiguration {
                reason: "syslog line has too few fields".to_string(),
            });
        }
        let severity = match parts[0].trim_start_matches('<').split_once('>') {
            Some((pri, _)) => {
                let pri_val: u8 = pri.parse().unwrap_or(6);
                match pri_val % 8 {
                    0 => "emergency",
                    1 => "alert",
                    2 => "critical",
                    3 => "error",
                    4 => "warning",
                    5 => "notice",
                    6 => "info",
                    _ => "debug",
                }.to_string()
            }
            None => "info".to_string(),
        };
        let service_name = parts[3].to_string();
        let message = parts[6].to_string();
        Ok(StructuredLogRecord {
            timestamp: 0,
            severity,
            service_name,
            message,
            fields: HashMap::from([
                ("hostname".to_string(), parts[2].to_string()),
                ("procid".to_string(), parts[4].to_string()),
                ("msgid".to_string(), parts[5].to_string()),
            ]),
            source_format: LogLineFormat::SyslogRfc5424,
        })
    }

    fn supported_formats(&self) -> Vec<LogLineFormat> {
        vec![LogLineFormat::SyslogRfc5424]
    }

    fn ingestor_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── JsonLinesIngestor ───────────────────────────────────────────

pub struct JsonLinesIngestor {
    id: String,
    records: Vec<StructuredLogRecord>,
}

impl JsonLinesIngestor {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string(), records: Vec::new() }
    }

    pub fn records(&self) -> &[StructuredLogRecord] {
        &self.records
    }
}

impl StructuredLogIngestor for JsonLinesIngestor {
    fn ingest_log(&mut self, record: StructuredLogRecord) -> Result<(), MonitoringError> {
        self.records.push(record);
        Ok(())
    }

    fn ingest_batch(&mut self, records: Vec<StructuredLogRecord>) -> IngestResult {
        let count = records.len();
        self.records.extend(records);
        IngestResult::success(count)
    }

    fn parse_log_line(&self, line: &str) -> Result<StructuredLogRecord, MonitoringError> {
        let parsed: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| MonitoringError::InvalidConfiguration {
                reason: format!("invalid JSON: {e}"),
            })?;
        let obj = parsed.as_object().ok_or_else(|| MonitoringError::InvalidConfiguration {
            reason: "JSON line is not an object".to_string(),
        })?;
        let timestamp = obj.get("timestamp")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let severity = obj.get("level").or(obj.get("severity"))
            .and_then(|v| v.as_str())
            .unwrap_or("info")
            .to_string();
        let service_name = obj.get("service").or(obj.get("service_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let message = obj.get("message").or(obj.get("msg"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let mut fields = HashMap::new();
        for (k, v) in obj {
            match k.as_str() {
                "timestamp" | "level" | "severity" | "service" | "service_name" | "message" | "msg" => {}
                _ => { fields.insert(k.clone(), v.to_string().trim_matches('"').to_string()); }
            }
        }
        Ok(StructuredLogRecord {
            timestamp,
            severity,
            service_name,
            message,
            fields,
            source_format: LogLineFormat::JsonLines,
        })
    }

    fn supported_formats(&self) -> Vec<LogLineFormat> {
        vec![LogLineFormat::JsonLines]
    }

    fn ingestor_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── NullLogIngestor ─────────────────────────────────────────────

pub struct NullLogIngestor {
    id: String,
}

impl NullLogIngestor {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl StructuredLogIngestor for NullLogIngestor {
    fn ingest_log(&mut self, _record: StructuredLogRecord) -> Result<(), MonitoringError> {
        Ok(())
    }

    fn ingest_batch(&mut self, records: Vec<StructuredLogRecord>) -> IngestResult {
        IngestResult::success(records.len())
    }

    fn parse_log_line(&self, _line: &str) -> Result<StructuredLogRecord, MonitoringError> {
        Ok(StructuredLogRecord::new(0, "info", "null", "", LogLineFormat::JsonLines))
    }

    fn supported_formats(&self) -> Vec<LogLineFormat> {
        vec![]
    }

    fn ingestor_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logfmt_parse() {
        let ingestor = LogfmtIngestor::new("lf-1");
        let record = ingestor.parse_log_line(r#"ts=1000 level=error msg="request failed" service=api path=/users"#).unwrap();
        assert_eq!(record.timestamp, 1000);
        assert_eq!(record.severity, "error");
        assert_eq!(record.message, "request failed");
        assert_eq!(record.service_name, "api");
        assert_eq!(record.fields.get("path").unwrap(), "/users");
        assert_eq!(record.source_format, LogLineFormat::LogfmtLine);
    }

    #[test]
    fn test_logfmt_ingest_and_batch() {
        let mut ingestor = LogfmtIngestor::new("lf-1");
        let record = StructuredLogRecord::new(1000, "info", "api", "ok", LogLineFormat::LogfmtLine);
        ingestor.ingest_log(record).unwrap();
        assert_eq!(ingestor.records().len(), 1);

        let batch = vec![
            StructuredLogRecord::new(1001, "warn", "api", "slow", LogLineFormat::LogfmtLine),
            StructuredLogRecord::new(1002, "error", "api", "fail", LogLineFormat::LogfmtLine),
        ];
        let result = ingestor.ingest_batch(batch);
        assert_eq!(result.ingested_count, 2);
        assert_eq!(result.failed_count, 0);
        assert_eq!(ingestor.records().len(), 3);
    }

    #[test]
    fn test_syslog_parse() {
        let ingestor = SyslogRfc5424Ingestor::new("sys-1");
        let line = "<14>1 2024-01-01T00:00:00Z host1 myapp 1234 ID47 Hello world";
        let record = ingestor.parse_log_line(line).unwrap();
        assert_eq!(record.severity, "info"); // priority 14 % 8 = 6 → info
        assert_eq!(record.service_name, "myapp");
        assert_eq!(record.message, "Hello world");
        assert_eq!(record.source_format, LogLineFormat::SyslogRfc5424);
    }

    #[test]
    fn test_syslog_parse_too_few_fields() {
        let ingestor = SyslogRfc5424Ingestor::new("sys-1");
        assert!(ingestor.parse_log_line("too short").is_err());
    }

    #[test]
    fn test_syslog_ingest() {
        let mut ingestor = SyslogRfc5424Ingestor::new("sys-1");
        let record = StructuredLogRecord::new(1000, "info", "api", "ok", LogLineFormat::SyslogRfc5424);
        ingestor.ingest_log(record).unwrap();
        assert_eq!(ingestor.records().len(), 1);
    }

    #[test]
    fn test_jsonlines_parse() {
        let ingestor = JsonLinesIngestor::new("jl-1");
        let line = r#"{"timestamp":2000,"level":"warn","service":"worker","message":"slow query","query_ms":150}"#;
        let record = ingestor.parse_log_line(line).unwrap();
        assert_eq!(record.timestamp, 2000);
        assert_eq!(record.severity, "warn");
        assert_eq!(record.service_name, "worker");
        assert_eq!(record.message, "slow query");
        assert_eq!(record.fields.get("query_ms").unwrap(), "150");
        assert_eq!(record.source_format, LogLineFormat::JsonLines);
    }

    #[test]
    fn test_jsonlines_parse_invalid() {
        let ingestor = JsonLinesIngestor::new("jl-1");
        assert!(ingestor.parse_log_line("not json").is_err());
    }

    #[test]
    fn test_jsonlines_ingest_batch() {
        let mut ingestor = JsonLinesIngestor::new("jl-1");
        let batch = vec![
            StructuredLogRecord::new(1000, "info", "api", "ok", LogLineFormat::JsonLines),
        ];
        let result = ingestor.ingest_batch(batch);
        assert_eq!(result.ingested_count, 1);
        assert_eq!(ingestor.records().len(), 1);
    }

    #[test]
    fn test_null_ingestor() {
        let mut ingestor = NullLogIngestor::new("null-1");
        let record = StructuredLogRecord::new(1000, "info", "api", "ok", LogLineFormat::JsonLines);
        ingestor.ingest_log(record).unwrap();
        assert!(!ingestor.is_active());
        let parsed = ingestor.parse_log_line("anything").unwrap();
        assert_eq!(parsed.service_name, "null");
    }

    #[test]
    fn test_log_line_format_display() {
        assert_eq!(LogLineFormat::EcsJson.to_string(), "ECS-JSON");
        assert_eq!(LogLineFormat::LogfmtLine.to_string(), "logfmt");
        assert_eq!(LogLineFormat::SyslogRfc5424.to_string(), "syslog-rfc5424");
        assert_eq!(LogLineFormat::CommonLogFormat.to_string(), "common-log-format");
        assert_eq!(LogLineFormat::JsonLines.to_string(), "json-lines");
        assert_eq!(LogLineFormat::OtelLogRecord.to_string(), "otel-log-record");
    }

    #[test]
    fn test_structured_log_record_with_field() {
        let record = StructuredLogRecord::new(1000, "info", "api", "ok", LogLineFormat::EcsJson)
            .with_field("trace_id", "abc123")
            .with_field("span_id", "def456");
        assert_eq!(record.fields.len(), 2);
        assert_eq!(record.fields.get("trace_id").unwrap(), "abc123");
    }

    #[test]
    fn test_ingest_result() {
        let success = IngestResult::success(5);
        assert_eq!(success.ingested_count, 5);
        assert_eq!(success.failed_count, 0);

        let partial = IngestResult::partial(3, 2, vec!["bad line".to_string()]);
        assert_eq!(partial.ingested_count, 3);
        assert_eq!(partial.failed_count, 2);
        assert_eq!(partial.errors.len(), 1);
    }

    #[test]
    fn test_supported_formats() {
        let lf = LogfmtIngestor::new("lf");
        assert_eq!(lf.supported_formats(), vec![LogLineFormat::LogfmtLine]);
        let sys = SyslogRfc5424Ingestor::new("sys");
        assert_eq!(sys.supported_formats(), vec![LogLineFormat::SyslogRfc5424]);
        let jl = JsonLinesIngestor::new("jl");
        assert_eq!(jl.supported_formats(), vec![LogLineFormat::JsonLines]);
        let null = NullLogIngestor::new("null");
        assert!(null.supported_formats().is_empty());
    }

    #[test]
    fn test_ingestor_ids() {
        let lf = LogfmtIngestor::new("lf-1");
        assert_eq!(lf.ingestor_id(), "lf-1");
        assert!(lf.is_active());
    }
}
