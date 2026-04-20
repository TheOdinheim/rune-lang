// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Agent communication audit chain.
//
// Cryptographic audit chain for all inter-agent communications
// using SHA3-256, with analytics and tamper detection.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use sha3::{Digest, Sha3_256};

// ── CommunicationRecord ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CommunicationRecord {
    pub id: String,
    pub from_agent: String,
    pub to_agent: String,
    pub message_type: String,
    pub payload_hash: String,
    pub previous_hash: Option<String>,
    pub record_hash: String,
    pub timestamp: i64,
    pub session_id: Option<String>,
}

// ── ChainVerification ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ChainVerification {
    pub valid: bool,
    pub verified_links: usize,
    pub broken_at: Option<usize>,
}

// ── Helper ────────────────────────────────────────────────────────

fn sha3_hex(data: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

fn compute_record_hash(
    id: &str,
    from: &str,
    to: &str,
    payload_hash: &str,
    previous_hash: &Option<String>,
    timestamp: i64,
) -> String {
    let prev = previous_hash.as_deref().unwrap_or("none");
    let input = format!("{id}||{from}||{to}||{payload_hash}||{prev}||{timestamp}");
    sha3_hex(&input)
}

// ── CommunicationChain ────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct CommunicationChain {
    records: Vec<CommunicationRecord>,
}

impl CommunicationChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(
        &mut self,
        from: &str,
        to: &str,
        message_type: &str,
        payload: &[u8],
        session_id: Option<&str>,
        now: i64,
    ) -> &CommunicationRecord {
        let id = format!("comm-{}", self.records.len());

        let mut hasher = Sha3_256::new();
        hasher.update(payload);
        let payload_hash = hex::encode(hasher.finalize());

        let previous_hash = self.records.last().map(|r| r.record_hash.clone());

        let record_hash =
            compute_record_hash(&id, from, to, &payload_hash, &previous_hash, now);

        self.records.push(CommunicationRecord {
            id,
            from_agent: from.to_string(),
            to_agent: to.to_string(),
            message_type: message_type.to_string(),
            payload_hash,
            previous_hash,
            record_hash,
            timestamp: now,
            session_id: session_id.map(|s| s.to_string()),
        });

        self.records.last().unwrap()
    }

    pub fn verify_chain(&self) -> ChainVerification {
        if self.records.is_empty() {
            return ChainVerification {
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
                return ChainVerification {
                    valid: false,
                    verified_links: i,
                    broken_at: Some(i),
                };
            }

            let expected_hash = compute_record_hash(
                &record.id,
                &record.from_agent,
                &record.to_agent,
                &record.payload_hash,
                &record.previous_hash,
                record.timestamp,
            );

            if record.record_hash != expected_hash {
                return ChainVerification {
                    valid: false,
                    verified_links: i,
                    broken_at: Some(i),
                };
            }
        }

        ChainVerification {
            valid: true,
            verified_links: self.records.len(),
            broken_at: None,
        }
    }

    pub fn chain_length(&self) -> usize {
        self.records.len()
    }

    pub fn records_for_agent(&self, agent_id: &str) -> Vec<&CommunicationRecord> {
        self.records
            .iter()
            .filter(|r| r.from_agent == agent_id || r.to_agent == agent_id)
            .collect()
    }

    pub fn records_for_session(&self, session_id: &str) -> Vec<&CommunicationRecord> {
        self.records
            .iter()
            .filter(|r| r.session_id.as_deref() == Some(session_id))
            .collect()
    }

    pub fn message_count_by_agent(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for r in &self.records {
            *counts.entry(r.from_agent.clone()).or_insert(0) += 1;
        }
        counts
    }

    pub fn busiest_pair(&self) -> Option<(String, String, usize)> {
        let mut pair_counts: HashMap<(String, String), usize> = HashMap::new();
        for r in &self.records {
            *pair_counts
                .entry((r.from_agent.clone(), r.to_agent.clone()))
                .or_insert(0) += 1;
        }
        pair_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|((from, to), count)| (from, to, count))
    }

    pub fn messages_in_window(&self, from_ts: i64, to_ts: i64) -> Vec<&CommunicationRecord> {
        self.records
            .iter()
            .filter(|r| r.timestamp >= from_ts && r.timestamp <= to_ts)
            .collect()
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
        let mut chain = CommunicationChain::new();
        chain.append("a1", "a2", "query", b"hello", None, 1000);
        chain.append("a2", "a1", "response", b"world", None, 1001);
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
        let mut chain = CommunicationChain::new();
        chain.append("a1", "a2", "query", b"hello", None, 1000);
        chain.append("a2", "a1", "response", b"world", None, 1001);
        chain.append("a1", "a2", "ack", b"ok", None, 1002);
        let verification = chain.verify_chain();
        assert!(verification.valid);
        assert_eq!(verification.verified_links, 3);
    }

    #[test]
    fn test_verify_chain_detects_tampering() {
        let mut chain = CommunicationChain::new();
        chain.append("a1", "a2", "query", b"hello", None, 1000);
        chain.append("a2", "a1", "response", b"world", None, 1001);
        // Tamper with record
        chain.records[0].record_hash = "tampered".to_string();
        let verification = chain.verify_chain();
        assert!(!verification.valid);
    }

    #[test]
    fn test_records_for_agent_returns_sender_and_receiver() {
        let mut chain = CommunicationChain::new();
        chain.append("a1", "a2", "query", b"msg1", None, 1000);
        chain.append("a3", "a1", "info", b"msg2", None, 1001);
        chain.append("a3", "a2", "info", b"msg3", None, 1002);
        let a1_records = chain.records_for_agent("a1");
        assert_eq!(a1_records.len(), 2); // sender in msg1, receiver in msg2
    }

    #[test]
    fn test_records_for_session() {
        let mut chain = CommunicationChain::new();
        chain.append("a1", "a2", "query", b"msg1", Some("s-1"), 1000);
        chain.append("a1", "a2", "info", b"msg2", None, 1001);
        chain.append("a1", "a2", "ack", b"msg3", Some("s-1"), 1002);
        let session_records = chain.records_for_session("s-1");
        assert_eq!(session_records.len(), 2);
    }

    #[test]
    fn test_message_count_by_agent() {
        let mut chain = CommunicationChain::new();
        chain.append("a1", "a2", "q", b"1", None, 1000);
        chain.append("a1", "a3", "q", b"2", None, 1001);
        chain.append("a2", "a1", "r", b"3", None, 1002);
        let counts = chain.message_count_by_agent();
        assert_eq!(counts.get("a1"), Some(&2));
        assert_eq!(counts.get("a2"), Some(&1));
    }

    #[test]
    fn test_busiest_pair() {
        let mut chain = CommunicationChain::new();
        chain.append("a1", "a2", "q", b"1", None, 1000);
        chain.append("a1", "a2", "q", b"2", None, 1001);
        chain.append("a1", "a2", "q", b"3", None, 1002);
        chain.append("a3", "a1", "r", b"4", None, 1003);
        let (from, to, count) = chain.busiest_pair().unwrap();
        assert_eq!(from, "a1");
        assert_eq!(to, "a2");
        assert_eq!(count, 3);
    }
}
