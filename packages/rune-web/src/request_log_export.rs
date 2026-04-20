// ═══════════════════════════════════════════════════════════════════════
// Request Log Export — Export formats for HTTP request/response logs.
//
// Layer 3 defines serialization formats for request governance logs.
// Bodies are never included in export. Authorization header values
// are redacted to "REDACTED" inside the exporter — defense in depth
// ensures redaction cannot be forgotten by the caller.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::error::WebError;
use crate::request::WebRequest;
use crate::response::WebResponse;

// ── RequestLogEntry ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RequestLogEntry {
    pub request_id: String,
    pub method: String,
    pub path: String,
    pub query_params: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub source_ip: String,
    pub identity: Option<String>,
    pub timestamp: i64,
    pub status_code: Option<u16>,
    pub response_headers: HashMap<String, String>,
    pub response_size_bytes: Option<u64>,
}

impl RequestLogEntry {
    pub fn from_request(request: &WebRequest) -> Self {
        let mut headers = request.headers.clone();
        redact_auth_headers(&mut headers);
        Self {
            request_id: request.id.clone(),
            method: format!("{}", request.method),
            path: request.path.clone(),
            query_params: request.query_params.clone(),
            headers,
            source_ip: request.source_ip.clone(),
            identity: request.identity.clone(),
            timestamp: request.timestamp,
            status_code: None,
            response_headers: HashMap::new(),
            response_size_bytes: None,
        }
    }

    pub fn with_response(mut self, response: &WebResponse) -> Self {
        self.status_code = Some(response.status_code);
        let mut resp_headers = response.headers.clone();
        redact_auth_headers(&mut resp_headers);
        self.response_headers = resp_headers;
        self.response_size_bytes = Some(response.body_size_bytes);
        self
    }
}

fn redact_auth_headers(headers: &mut HashMap<String, String>) {
    let keys_to_redact: Vec<String> = headers
        .keys()
        .filter(|k| k.to_lowercase() == "authorization")
        .cloned()
        .collect();
    for key in keys_to_redact {
        headers.insert(key, "REDACTED".to_string());
    }
}

// ── RequestLogExporter trait ───────────────────────────────────

pub trait RequestLogExporter {
    fn export_request_log(&self, entry: &RequestLogEntry) -> Result<Vec<u8>, WebError>;
    fn export_batch(&self, entries: &[&RequestLogEntry]) -> Result<Vec<u8>, WebError>;
    fn format_name(&self) -> &str;
    fn content_type(&self) -> &str;
}

// ── JsonRequestLogExporter ─────────────────────────────────────

pub struct JsonRequestLogExporter;

impl JsonRequestLogExporter {
    pub fn new() -> Self { Self }
}

impl Default for JsonRequestLogExporter {
    fn default() -> Self { Self::new() }
}

fn entry_to_json(e: &RequestLogEntry) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "request_id": e.request_id,
        "method": e.method,
        "path": e.path,
        "source_ip": e.source_ip,
        "timestamp": e.timestamp,
        "headers": e.headers,
    });
    if !e.query_params.is_empty() {
        obj["query_params"] = serde_json::json!(e.query_params);
    }
    if let Some(ref id) = e.identity {
        obj["identity"] = serde_json::json!(id);
    }
    if let Some(status) = e.status_code {
        obj["response"] = serde_json::json!({
            "status_code": status,
            "headers": e.response_headers,
            "size_bytes": e.response_size_bytes,
        });
    }
    obj
}

impl RequestLogExporter for JsonRequestLogExporter {
    fn export_request_log(&self, entry: &RequestLogEntry) -> Result<Vec<u8>, WebError> {
        serde_json::to_vec_pretty(&entry_to_json(entry))
            .map_err(|e| WebError::InvalidConfiguration(format!("JSON export: {e}")))
    }

    fn export_batch(&self, entries: &[&RequestLogEntry]) -> Result<Vec<u8>, WebError> {
        let arr: Vec<serde_json::Value> = entries.iter().map(|e| entry_to_json(e)).collect();
        serde_json::to_vec_pretty(&arr)
            .map_err(|e| WebError::InvalidConfiguration(format!("JSON batch: {e}")))
    }

    fn format_name(&self) -> &str { "json" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── CommonLogFormatExporter ────────────────────────────────────

/// Apache CLF: host ident authuser date request status size
pub struct CommonLogFormatExporter;

impl CommonLogFormatExporter {
    pub fn new() -> Self { Self }
}

impl Default for CommonLogFormatExporter {
    fn default() -> Self { Self::new() }
}

impl RequestLogExporter for CommonLogFormatExporter {
    fn export_request_log(&self, entry: &RequestLogEntry) -> Result<Vec<u8>, WebError> {
        let authuser = entry.identity.as_deref().unwrap_or("-");
        let status = entry.status_code.map(|s| s.to_string()).unwrap_or_else(|| "-".to_string());
        let size = entry.response_size_bytes.map(|s| s.to_string()).unwrap_or_else(|| "-".to_string());
        let line = format!(
            "{} - {} [{}] \"{} {} HTTP/1.1\" {} {}",
            entry.source_ip, authuser, entry.timestamp, entry.method, entry.path, status, size,
        );
        Ok(line.into_bytes())
    }

    fn export_batch(&self, entries: &[&RequestLogEntry]) -> Result<Vec<u8>, WebError> {
        let lines: Result<Vec<Vec<u8>>, WebError> = entries.iter().map(|e| self.export_request_log(e)).collect();
        let lines = lines?;
        let joined: Vec<u8> = lines
            .into_iter()
            .flat_map(|mut line| { line.push(b'\n'); line })
            .collect();
        Ok(joined)
    }

    fn format_name(&self) -> &str { "clf" }
    fn content_type(&self) -> &str { "text/plain" }
}

// ── CombinedLogFormatExporter ──────────────────────────────────

/// Apache combined: CLF + referer + user-agent
pub struct CombinedLogFormatExporter;

impl CombinedLogFormatExporter {
    pub fn new() -> Self { Self }
}

impl Default for CombinedLogFormatExporter {
    fn default() -> Self { Self::new() }
}

impl RequestLogExporter for CombinedLogFormatExporter {
    fn export_request_log(&self, entry: &RequestLogEntry) -> Result<Vec<u8>, WebError> {
        let authuser = entry.identity.as_deref().unwrap_or("-");
        let status = entry.status_code.map(|s| s.to_string()).unwrap_or_else(|| "-".to_string());
        let size = entry.response_size_bytes.map(|s| s.to_string()).unwrap_or_else(|| "-".to_string());
        let referer = entry.headers.iter()
            .find(|(k, _)| k.to_lowercase() == "referer")
            .map(|(_, v)| v.as_str())
            .unwrap_or("-");
        let ua = entry.headers.iter()
            .find(|(k, _)| k.to_lowercase() == "user-agent")
            .map(|(_, v)| v.as_str())
            .unwrap_or("-");
        let line = format!(
            "{} - {} [{}] \"{} {} HTTP/1.1\" {} {} \"{}\" \"{}\"",
            entry.source_ip, authuser, entry.timestamp, entry.method, entry.path, status, size, referer, ua,
        );
        Ok(line.into_bytes())
    }

    fn export_batch(&self, entries: &[&RequestLogEntry]) -> Result<Vec<u8>, WebError> {
        let lines: Result<Vec<Vec<u8>>, WebError> = entries.iter().map(|e| self.export_request_log(e)).collect();
        let lines = lines?;
        let joined: Vec<u8> = lines
            .into_iter()
            .flat_map(|mut line| { line.push(b'\n'); line })
            .collect();
        Ok(joined)
    }

    fn format_name(&self) -> &str { "combined" }
    fn content_type(&self) -> &str { "text/plain" }
}

// ── EcsHttpExporter ────────────────────────────────────────────

/// Elastic Common Schema http.* and url.* fields.
pub struct EcsHttpExporter;

impl EcsHttpExporter {
    pub fn new() -> Self { Self }
}

impl Default for EcsHttpExporter {
    fn default() -> Self { Self::new() }
}

impl RequestLogExporter for EcsHttpExporter {
    fn export_request_log(&self, entry: &RequestLogEntry) -> Result<Vec<u8>, WebError> {
        let mut ecs = serde_json::json!({
            "http": {
                "request": {
                    "method": entry.method,
                },
            },
            "url": {
                "path": entry.path,
            },
            "source": {
                "ip": entry.source_ip,
            },
            "@timestamp": entry.timestamp,
        });
        if let Some(status) = entry.status_code {
            ecs["http"]["response"] = serde_json::json!({
                "status_code": status,
            });
        }
        if let Some(size) = entry.response_size_bytes {
            ecs["http"]["response"]["body"] = serde_json::json!({ "bytes": size });
        }
        serde_json::to_vec_pretty(&ecs)
            .map_err(|e| WebError::InvalidConfiguration(format!("ECS export: {e}")))
    }

    fn export_batch(&self, entries: &[&RequestLogEntry]) -> Result<Vec<u8>, WebError> {
        let arr: Vec<serde_json::Value> = entries.iter().map(|e| {
            serde_json::json!({
                "http": { "request": { "method": e.method } },
                "url": { "path": e.path },
                "@timestamp": e.timestamp,
            })
        }).collect();
        serde_json::to_vec_pretty(&arr)
            .map_err(|e| WebError::InvalidConfiguration(format!("ECS batch: {e}")))
    }

    fn format_name(&self) -> &str { "ecs" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── OtelHttpExporter ───────────────────────────────────────────

/// OpenTelemetry HTTP semantic conventions.
pub struct OtelHttpExporter;

impl OtelHttpExporter {
    pub fn new() -> Self { Self }
}

impl Default for OtelHttpExporter {
    fn default() -> Self { Self::new() }
}

impl RequestLogExporter for OtelHttpExporter {
    fn export_request_log(&self, entry: &RequestLogEntry) -> Result<Vec<u8>, WebError> {
        let host = entry.headers.iter()
            .find(|(k, _)| k.to_lowercase() == "host")
            .map(|(_, v)| v.as_str())
            .unwrap_or("unknown");
        let mut otel = serde_json::json!({
            "http.request.method": entry.method,
            "server.address": host,
            "url.path": entry.path,
            "url.scheme": "https",
            "client.address": entry.source_ip,
            "timestamp": entry.timestamp,
        });
        if let Some(status) = entry.status_code {
            otel["http.response.status_code"] = serde_json::json!(status);
        }
        serde_json::to_vec_pretty(&otel)
            .map_err(|e| WebError::InvalidConfiguration(format!("OTel export: {e}")))
    }

    fn export_batch(&self, entries: &[&RequestLogEntry]) -> Result<Vec<u8>, WebError> {
        let arr: Vec<serde_json::Value> = entries.iter().map(|e| {
            serde_json::json!({
                "http.request.method": e.method,
                "url.path": e.path,
                "timestamp": e.timestamp,
            })
        }).collect();
        serde_json::to_vec_pretty(&arr)
            .map_err(|e| WebError::InvalidConfiguration(format!("OTel batch: {e}")))
    }

    fn format_name(&self) -> &str { "otel" }
    fn content_type(&self) -> &str { "application/json" }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::HttpMethod;

    fn make_entry() -> RequestLogEntry {
        let req = WebRequest::new("req-1", HttpMethod::Get, "/api/v1/users", "1.2.3.4", 1000)
            .with_header("Host", "example.com")
            .with_header("Authorization", "Bearer secret-token")
            .with_header("User-Agent", "TestClient/1.0");
        let resp = WebResponse::new(200)
            .with_header("Content-Type", "application/json")
            .with_body(r#"{"ok":true}"#);
        RequestLogEntry::from_request(&req).with_response(&resp)
    }

    #[test]
    fn test_auth_header_redacted() {
        let entry = make_entry();
        assert_eq!(entry.headers.get("Authorization").unwrap(), "REDACTED");
    }

    #[test]
    fn test_json_exporter() {
        let exp = JsonRequestLogExporter::new();
        let entry = make_entry();
        let data = exp.export_request_log(&entry).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(parsed["method"], "GET");
        assert_eq!(parsed["path"], "/api/v1/users");
        assert_eq!(parsed["headers"]["Authorization"], "REDACTED");
        assert!(parsed.get("body").is_none()); // body never included
    }

    #[test]
    fn test_json_batch() {
        let exp = JsonRequestLogExporter::new();
        let entry = make_entry();
        let data = exp.export_batch(&[&entry]).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_slice(&data).unwrap();
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn test_clf_exporter() {
        let exp = CommonLogFormatExporter::new();
        let entry = make_entry();
        let data = exp.export_request_log(&entry).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("1.2.3.4"));
        assert!(text.contains("GET /api/v1/users"));
        assert!(text.contains("200"));
        assert!(!text.contains("secret-token"));
    }

    #[test]
    fn test_combined_exporter() {
        let exp = CombinedLogFormatExporter::new();
        let entry = make_entry();
        let data = exp.export_request_log(&entry).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("TestClient/1.0"));
        assert!(!text.contains("secret-token"));
    }

    #[test]
    fn test_ecs_exporter() {
        let exp = EcsHttpExporter::new();
        let entry = make_entry();
        let data = exp.export_request_log(&entry).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(parsed["http"]["request"]["method"], "GET");
        assert_eq!(parsed["url"]["path"], "/api/v1/users");
        assert_eq!(parsed["http"]["response"]["status_code"], 200);
    }

    #[test]
    fn test_otel_exporter() {
        let exp = OtelHttpExporter::new();
        let entry = make_entry();
        let data = exp.export_request_log(&entry).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(parsed["http.request.method"], "GET");
        assert_eq!(parsed["url.path"], "/api/v1/users");
        assert_eq!(parsed["http.response.status_code"], 200);
        assert_eq!(parsed["server.address"], "example.com");
    }

    #[test]
    fn test_format_names() {
        assert_eq!(JsonRequestLogExporter::new().format_name(), "json");
        assert_eq!(CommonLogFormatExporter::new().format_name(), "clf");
        assert_eq!(CombinedLogFormatExporter::new().format_name(), "combined");
        assert_eq!(EcsHttpExporter::new().format_name(), "ecs");
        assert_eq!(OtelHttpExporter::new().format_name(), "otel");
    }

    #[test]
    fn test_content_types() {
        assert_eq!(JsonRequestLogExporter::new().content_type(), "application/json");
        assert_eq!(CommonLogFormatExporter::new().content_type(), "text/plain");
        assert_eq!(EcsHttpExporter::new().content_type(), "application/json");
    }

    #[test]
    fn test_entry_without_response() {
        let req = WebRequest::new("req-1", HttpMethod::Get, "/test", "1.2.3.4", 1000)
            .with_header("Host", "example.com");
        let entry = RequestLogEntry::from_request(&req);
        assert!(entry.status_code.is_none());
        let exp = JsonRequestLogExporter::new();
        let data = exp.export_request_log(&entry).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert!(parsed.get("response").is_none());
    }
}
