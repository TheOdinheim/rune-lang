// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Network traffic audit chain.
//
// Cryptographic audit chain for network traffic decisions using
// SHA3-256, with tamper detection and analytics.
// ═══════════════════════════════════════════════════════════════════════

use sha3::{Digest, Sha3_256};

// ── Helper ───────────────────────────────────────────────────────

fn sha3_hex(data: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

fn compute_record_hash(
    id: &str,
    source: &str,
    destination: &str,
    port: u16,
    action: &str,
    previous_hash: &Option<String>,
    timestamp: i64,
) -> String {
    let prev = previous_hash.as_deref().unwrap_or("none");
    let input = format!("{id}||{source}||{destination}||{port}||{action}||{prev}||{timestamp}");
    sha3_hex(&input)
}

// ── TrafficRecord ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TrafficRecord {
    pub id: String,
    pub direction: String,
    pub source: String,
    pub destination: String,
    pub port: u16,
    pub protocol: String,
    pub action: String,
    pub policy_id: Option<String>,
    pub payload_size_bytes: u64,
    pub timestamp: i64,
    pub previous_hash: Option<String>,
    pub record_hash: String,
}

// ── TrafficChainVerification ─────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TrafficChainVerification {
    pub valid: bool,
    pub verified_links: usize,
    pub broken_at: Option<usize>,
}

// ── TrafficAuditChain ────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct TrafficAuditChain {
    records: Vec<TrafficRecord>,
}

impl TrafficAuditChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(
        &mut self,
        direction: &str,
        source: &str,
        destination: &str,
        port: u16,
        protocol: &str,
        action: &str,
        policy_id: Option<&str>,
        payload_size: u64,
        now: i64,
    ) -> &TrafficRecord {
        let id = format!("traffic-{}", self.records.len());

        let previous_hash = self.records.last().map(|r| r.record_hash.clone());

        let record_hash =
            compute_record_hash(&id, source, destination, port, action, &previous_hash, now);

        self.records.push(TrafficRecord {
            id,
            direction: direction.to_string(),
            source: source.to_string(),
            destination: destination.to_string(),
            port,
            protocol: protocol.to_string(),
            action: action.to_string(),
            policy_id: policy_id.map(|s| s.to_string()),
            payload_size_bytes: payload_size,
            timestamp: now,
            previous_hash,
            record_hash,
        });

        self.records.last().unwrap()
    }

    pub fn verify_chain(&self) -> TrafficChainVerification {
        if self.records.is_empty() {
            return TrafficChainVerification {
                valid: true,
                verified_links: 0,
                broken_at: None,
            };
        }

        for (i, record) in self.records.iter().enumerate() {
            let expected_prev = if i == 0 {
                None
            } else {
                Some(self.records[i - 1].record_hash.clone())
            };

            if record.previous_hash != expected_prev {
                return TrafficChainVerification {
                    valid: false,
                    verified_links: i,
                    broken_at: Some(i),
                };
            }

            let expected_hash = compute_record_hash(
                &record.id,
                &record.source,
                &record.destination,
                record.port,
                &record.action,
                &record.previous_hash,
                record.timestamp,
            );

            if record.record_hash != expected_hash {
                return TrafficChainVerification {
                    valid: false,
                    verified_links: i,
                    broken_at: Some(i),
                };
            }
        }

        TrafficChainVerification {
            valid: true,
            verified_links: self.records.len(),
            broken_at: None,
        }
    }

    pub fn chain_length(&self) -> usize {
        self.records.len()
    }

    pub fn records_for_source(&self, source: &str) -> Vec<&TrafficRecord> {
        self.records
            .iter()
            .filter(|r| r.source == source)
            .collect()
    }

    pub fn records_for_destination(&self, destination: &str) -> Vec<&TrafficRecord> {
        self.records
            .iter()
            .filter(|r| r.destination == destination)
            .collect()
    }

    pub fn denied_traffic(&self) -> Vec<&TrafficRecord> {
        self.records
            .iter()
            .filter(|r| r.action == "deny")
            .collect()
    }

    pub fn traffic_volume_bytes(&self) -> u64 {
        self.records.iter().map(|r| r.payload_size_bytes).sum()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_creates_chained_records() {
        let mut chain = TrafficAuditChain::new();
        chain.append("inbound", "1.2.3.4", "10.0.0.1", 443, "TCP", "allow", None, 1024, 1000);
        chain.append("outbound", "10.0.0.1", "1.2.3.4", 443, "TCP", "allow", None, 512, 1001);
        assert_eq!(chain.chain_length(), 2);
        assert!(chain.records[0].previous_hash.is_none());
        assert!(chain.records[1].previous_hash.is_some());
        assert_eq!(
            chain.records[1].previous_hash.as_ref().unwrap(),
            &chain.records[0].record_hash
        );
    }

    #[test]
    fn test_verify_chain_passes_for_valid() {
        let mut chain = TrafficAuditChain::new();
        chain.append("inbound", "1.2.3.4", "10.0.0.1", 443, "TCP", "allow", None, 100, 1000);
        chain.append("inbound", "5.6.7.8", "10.0.0.1", 80, "TCP", "deny", Some("p1"), 200, 1001);
        chain.append("outbound", "10.0.0.1", "1.2.3.4", 443, "TCP", "allow", None, 50, 1002);
        let verification = chain.verify_chain();
        assert!(verification.valid);
        assert_eq!(verification.verified_links, 3);
    }

    #[test]
    fn test_verify_chain_detects_tampering() {
        let mut chain = TrafficAuditChain::new();
        chain.append("inbound", "1.2.3.4", "10.0.0.1", 443, "TCP", "allow", None, 100, 1000);
        chain.append("inbound", "5.6.7.8", "10.0.0.1", 80, "TCP", "deny", None, 200, 1001);
        chain.records[0].record_hash = "tampered".to_string();
        let verification = chain.verify_chain();
        assert!(!verification.valid);
    }

    #[test]
    fn test_records_for_source() {
        let mut chain = TrafficAuditChain::new();
        chain.append("inbound", "1.2.3.4", "10.0.0.1", 443, "TCP", "allow", None, 100, 1000);
        chain.append("inbound", "5.6.7.8", "10.0.0.1", 80, "TCP", "deny", None, 200, 1001);
        chain.append("inbound", "1.2.3.4", "10.0.0.2", 22, "TCP", "allow", None, 50, 1002);
        assert_eq!(chain.records_for_source("1.2.3.4").len(), 2);
    }

    #[test]
    fn test_denied_traffic() {
        let mut chain = TrafficAuditChain::new();
        chain.append("inbound", "1.2.3.4", "10.0.0.1", 443, "TCP", "allow", None, 100, 1000);
        chain.append("inbound", "5.6.7.8", "10.0.0.1", 80, "TCP", "deny", None, 200, 1001);
        chain.append("inbound", "9.8.7.6", "10.0.0.1", 22, "TCP", "deny", None, 50, 1002);
        assert_eq!(chain.denied_traffic().len(), 2);
    }

    #[test]
    fn test_traffic_volume_bytes() {
        let mut chain = TrafficAuditChain::new();
        chain.append("inbound", "1.2.3.4", "10.0.0.1", 443, "TCP", "allow", None, 100, 1000);
        chain.append("inbound", "5.6.7.8", "10.0.0.1", 80, "TCP", "allow", None, 200, 1001);
        chain.append("outbound", "10.0.0.1", "1.2.3.4", 443, "TCP", "allow", None, 50, 1002);
        assert_eq!(chain.traffic_volume_bytes(), 350);
    }
}
