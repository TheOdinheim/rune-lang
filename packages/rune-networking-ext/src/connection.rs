// ═══════════════════════════════════════════════════════════════════════
// Connection — Connection lifecycle, authentication, and authorization.
// Every network connection is tracked from open to close.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::NetworkError;
use crate::protocol::{CipherSuite, TlsVersion};
use crate::traffic::TrustLevel;

// ── ConnectionId ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnectionId(pub String);

impl ConnectionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── ConnectionProtocol ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionProtocol {
    Tcp,
    Udp,
    Tls,
    MTls,
    Quic,
    WebSocket,
    Custom(String),
}

impl fmt::Display for ConnectionProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Tls => write!(f, "TLS"),
            Self::MTls => write!(f, "mTLS"),
            Self::Quic => write!(f, "QUIC"),
            Self::WebSocket => write!(f, "WebSocket"),
            Self::Custom(name) => write!(f, "Custom({name})"),
        }
    }
}

// ── ConnectionState ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Pending,
    Authenticating,
    Established,
    Idle { since: i64 },
    Draining,
    Closed { reason: String },
    Rejected { reason: String },
}

impl ConnectionState {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Established | Self::Authenticating)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Closed { .. } | Self::Rejected { .. })
    }
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Authenticating => write!(f, "Authenticating"),
            Self::Established => write!(f, "Established"),
            Self::Idle { since } => write!(f, "Idle(since={since})"),
            Self::Draining => write!(f, "Draining"),
            Self::Closed { reason } => write!(f, "Closed: {reason}"),
            Self::Rejected { reason } => write!(f, "Rejected: {reason}"),
        }
    }
}

// ── Connection ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub id: ConnectionId,
    pub source_addr: String,
    pub dest_addr: String,
    pub protocol: ConnectionProtocol,
    pub tls_version: Option<TlsVersion>,
    pub cipher_suite: Option<CipherSuite>,
    pub state: ConnectionState,
    pub trust_level: TrustLevel,
    pub identity: Option<String>,
    pub established_at: i64,
    pub last_activity: i64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub metadata: HashMap<String, String>,
}

// ── ConnectionStore ─────────────────────────────────────────────────

pub struct ConnectionStore {
    connections: HashMap<ConnectionId, Connection>,
    counter: u64,
    max_connections: usize,
}

impl ConnectionStore {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            counter: 0,
            max_connections: 10_000,
        }
    }

    pub fn with_max(max: usize) -> Self {
        Self {
            connections: HashMap::new(),
            counter: 0,
            max_connections: max,
        }
    }

    pub fn open(
        &mut self,
        source: &str,
        dest: &str,
        protocol: ConnectionProtocol,
        now: i64,
    ) -> Result<ConnectionId, NetworkError> {
        let active = self.active_count();
        if active >= self.max_connections {
            return Err(NetworkError::ConnectionLimitReached {
                max: self.max_connections,
            });
        }
        self.counter += 1;
        let id = ConnectionId::new(format!("conn_{:08x}", self.counter));
        let conn = Connection {
            id: id.clone(),
            source_addr: source.into(),
            dest_addr: dest.into(),
            protocol,
            tls_version: None,
            cipher_suite: None,
            state: ConnectionState::Pending,
            trust_level: TrustLevel::Untrusted,
            identity: None,
            established_at: now,
            last_activity: now,
            bytes_sent: 0,
            bytes_received: 0,
            metadata: HashMap::new(),
        };
        self.connections.insert(id.clone(), conn);
        Ok(id)
    }

    pub fn get(&self, id: &ConnectionId) -> Option<&Connection> {
        self.connections.get(id)
    }

    pub fn get_mut(&mut self, id: &ConnectionId) -> Option<&mut Connection> {
        self.connections.get_mut(id)
    }

    pub fn authenticate(
        &mut self,
        id: &ConnectionId,
        identity: &str,
        trust_level: TrustLevel,
    ) -> Result<(), NetworkError> {
        let conn = self
            .connections
            .get_mut(id)
            .ok_or_else(|| NetworkError::ConnectionNotFound(id.0.clone()))?;
        conn.identity = Some(identity.into());
        conn.trust_level = trust_level;
        conn.state = ConnectionState::Authenticating;
        Ok(())
    }

    pub fn establish(
        &mut self,
        id: &ConnectionId,
        tls_version: Option<TlsVersion>,
        cipher: Option<CipherSuite>,
        now: i64,
    ) -> Result<(), NetworkError> {
        let conn = self
            .connections
            .get_mut(id)
            .ok_or_else(|| NetworkError::ConnectionNotFound(id.0.clone()))?;
        conn.tls_version = tls_version;
        conn.cipher_suite = cipher;
        conn.state = ConnectionState::Established;
        conn.last_activity = now;
        Ok(())
    }

    pub fn close(
        &mut self,
        id: &ConnectionId,
        reason: &str,
        now: i64,
    ) -> Result<(), NetworkError> {
        let conn = self
            .connections
            .get_mut(id)
            .ok_or_else(|| NetworkError::ConnectionNotFound(id.0.clone()))?;
        conn.state = ConnectionState::Closed {
            reason: reason.into(),
        };
        conn.last_activity = now;
        Ok(())
    }

    pub fn reject(&mut self, id: &ConnectionId, reason: &str) -> Result<(), NetworkError> {
        let conn = self
            .connections
            .get_mut(id)
            .ok_or_else(|| NetworkError::ConnectionNotFound(id.0.clone()))?;
        conn.state = ConnectionState::Rejected {
            reason: reason.into(),
        };
        Ok(())
    }

    pub fn record_traffic(
        &mut self,
        id: &ConnectionId,
        sent: u64,
        received: u64,
        now: i64,
    ) -> Result<(), NetworkError> {
        let conn = self
            .connections
            .get_mut(id)
            .ok_or_else(|| NetworkError::ConnectionNotFound(id.0.clone()))?;
        conn.bytes_sent += sent;
        conn.bytes_received += received;
        conn.last_activity = now;
        Ok(())
    }

    pub fn active_connections(&self) -> Vec<&Connection> {
        self.connections
            .values()
            .filter(|c| c.state == ConnectionState::Established)
            .collect()
    }

    pub fn connections_from(&self, source: &str) -> Vec<&Connection> {
        self.connections
            .values()
            .filter(|c| c.source_addr == source)
            .collect()
    }

    pub fn connections_to(&self, dest: &str) -> Vec<&Connection> {
        self.connections
            .values()
            .filter(|c| c.dest_addr == dest)
            .collect()
    }

    pub fn idle_connections(&self, idle_threshold_ms: i64, now: i64) -> Vec<&Connection> {
        self.connections
            .values()
            .filter(|c| {
                c.state == ConnectionState::Established
                    && (now - c.last_activity) >= idle_threshold_ms
            })
            .collect()
    }

    pub fn close_idle(&mut self, idle_threshold_ms: i64, now: i64) -> usize {
        let ids: Vec<ConnectionId> = self
            .connections
            .values()
            .filter(|c| {
                c.state == ConnectionState::Established
                    && (now - c.last_activity) >= idle_threshold_ms
            })
            .map(|c| c.id.clone())
            .collect();
        let count = ids.len();
        for id in &ids {
            if let Some(conn) = self.connections.get_mut(id) {
                conn.state = ConnectionState::Closed {
                    reason: "idle timeout".into(),
                };
                conn.last_activity = now;
            }
        }
        count
    }

    pub fn active_count(&self) -> usize {
        self.connections
            .values()
            .filter(|c| !c.state.is_terminal())
            .count()
    }

    pub fn total_bytes_transferred(&self) -> (u64, u64) {
        self.connections
            .values()
            .fold((0u64, 0u64), |(s, r), c| (s + c.bytes_sent, r + c.bytes_received))
    }

    pub fn count(&self) -> usize {
        self.connections.len()
    }
}

impl Default for ConnectionStore {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_creates_pending_connection() {
        let mut store = ConnectionStore::new();
        let id = store.open("1.2.3.4:5000", "5.6.7.8:443", ConnectionProtocol::Tls, 1000).unwrap();
        let conn = store.get(&id).unwrap();
        assert_eq!(conn.state, ConnectionState::Pending);
        assert_eq!(conn.source_addr, "1.2.3.4:5000");
    }

    #[test]
    fn test_open_rejects_at_max_connections() {
        let mut store = ConnectionStore::with_max(1);
        store.open("1.2.3.4:5000", "5.6.7.8:443", ConnectionProtocol::Tcp, 1000).unwrap();
        let r = store.open("1.2.3.4:5001", "5.6.7.8:443", ConnectionProtocol::Tcp, 1001);
        assert!(r.is_err());
    }

    #[test]
    fn test_authenticate_updates_identity_and_trust() {
        let mut store = ConnectionStore::new();
        let id = store.open("1.2.3.4:5000", "5.6.7.8:443", ConnectionProtocol::Tls, 1000).unwrap();
        store.authenticate(&id, "user@example.com", TrustLevel::Trusted).unwrap();
        let conn = store.get(&id).unwrap();
        assert_eq!(conn.identity.as_deref(), Some("user@example.com"));
        assert_eq!(conn.trust_level, TrustLevel::Trusted);
    }

    #[test]
    fn test_establish_sets_tls_and_cipher() {
        let mut store = ConnectionStore::new();
        let id = store.open("1.2.3.4:5000", "5.6.7.8:443", ConnectionProtocol::Tls, 1000).unwrap();
        store.establish(&id, Some(TlsVersion::Tls13), Some(CipherSuite::Aes256GcmSha384), 2000).unwrap();
        let conn = store.get(&id).unwrap();
        assert_eq!(conn.state, ConnectionState::Established);
        assert_eq!(conn.tls_version, Some(TlsVersion::Tls13));
    }

    #[test]
    fn test_close_updates_state() {
        let mut store = ConnectionStore::new();
        let id = store.open("1.2.3.4:5000", "5.6.7.8:443", ConnectionProtocol::Tcp, 1000).unwrap();
        store.establish(&id, None, None, 2000).unwrap();
        store.close(&id, "done", 3000).unwrap();
        assert!(matches!(store.get(&id).unwrap().state, ConnectionState::Closed { .. }));
    }

    #[test]
    fn test_reject_updates_state() {
        let mut store = ConnectionStore::new();
        let id = store.open("1.2.3.4:5000", "5.6.7.8:443", ConnectionProtocol::Tcp, 1000).unwrap();
        store.reject(&id, "policy").unwrap();
        assert!(matches!(store.get(&id).unwrap().state, ConnectionState::Rejected { .. }));
    }

    #[test]
    fn test_record_traffic_increments_bytes() {
        let mut store = ConnectionStore::new();
        let id = store.open("1.2.3.4:5000", "5.6.7.8:443", ConnectionProtocol::Tcp, 1000).unwrap();
        store.establish(&id, None, None, 2000).unwrap();
        store.record_traffic(&id, 100, 200, 3000).unwrap();
        store.record_traffic(&id, 50, 75, 4000).unwrap();
        let conn = store.get(&id).unwrap();
        assert_eq!(conn.bytes_sent, 150);
        assert_eq!(conn.bytes_received, 275);
    }

    #[test]
    fn test_active_connections_returns_established() {
        let mut store = ConnectionStore::new();
        let id1 = store.open("1.2.3.4:5000", "5.6.7.8:443", ConnectionProtocol::Tcp, 1000).unwrap();
        let id2 = store.open("1.2.3.4:5001", "5.6.7.8:443", ConnectionProtocol::Tcp, 1000).unwrap();
        store.establish(&id1, None, None, 2000).unwrap();
        // id2 still Pending
        assert_eq!(store.active_connections().len(), 1);
        let _ = id2;
    }

    #[test]
    fn test_connections_from_filters_by_source() {
        let mut store = ConnectionStore::new();
        store.open("1.2.3.4:5000", "5.6.7.8:443", ConnectionProtocol::Tcp, 1000).unwrap();
        store.open("9.8.7.6:5000", "5.6.7.8:443", ConnectionProtocol::Tcp, 1000).unwrap();
        assert_eq!(store.connections_from("1.2.3.4:5000").len(), 1);
    }

    #[test]
    fn test_connections_to_filters_by_destination() {
        let mut store = ConnectionStore::new();
        store.open("1.2.3.4:5000", "5.6.7.8:443", ConnectionProtocol::Tcp, 1000).unwrap();
        store.open("1.2.3.4:5001", "9.8.7.6:80", ConnectionProtocol::Tcp, 1000).unwrap();
        assert_eq!(store.connections_to("5.6.7.8:443").len(), 1);
    }

    #[test]
    fn test_idle_connections() {
        let mut store = ConnectionStore::new();
        let id = store.open("1.2.3.4:5000", "5.6.7.8:443", ConnectionProtocol::Tcp, 1000).unwrap();
        store.establish(&id, None, None, 1000).unwrap();
        assert_eq!(store.idle_connections(5000, 7000).len(), 1);
        assert_eq!(store.idle_connections(5000, 3000).len(), 0);
    }

    #[test]
    fn test_close_idle_closes_and_returns_count() {
        let mut store = ConnectionStore::new();
        let id1 = store.open("1.2.3.4:5000", "5.6.7.8:443", ConnectionProtocol::Tcp, 1000).unwrap();
        let id2 = store.open("1.2.3.4:5001", "5.6.7.8:443", ConnectionProtocol::Tcp, 1000).unwrap();
        store.establish(&id1, None, None, 1000).unwrap();
        store.establish(&id2, None, None, 5000).unwrap();
        let closed = store.close_idle(3000, 6000);
        assert_eq!(closed, 1); // id1 idle since 1000, now 6000 (5000ms >= 3000)
    }

    #[test]
    fn test_total_bytes_transferred() {
        let mut store = ConnectionStore::new();
        let id1 = store.open("1.2.3.4:5000", "5.6.7.8:443", ConnectionProtocol::Tcp, 1000).unwrap();
        let id2 = store.open("1.2.3.4:5001", "5.6.7.8:443", ConnectionProtocol::Tcp, 1000).unwrap();
        store.record_traffic(&id1, 100, 200, 2000).unwrap();
        store.record_traffic(&id2, 50, 75, 2000).unwrap();
        assert_eq!(store.total_bytes_transferred(), (150, 275));
    }

    #[test]
    fn test_connection_protocol_display() {
        let protos = vec![
            ConnectionProtocol::Tcp,
            ConnectionProtocol::Udp,
            ConnectionProtocol::Tls,
            ConnectionProtocol::MTls,
            ConnectionProtocol::Quic,
            ConnectionProtocol::WebSocket,
            ConnectionProtocol::Custom("P25".into()),
        ];
        for p in &protos {
            assert!(!p.to_string().is_empty());
        }
        assert_eq!(protos.len(), 7);
    }

    #[test]
    fn test_connection_state_is_active_and_is_terminal() {
        assert!(ConnectionState::Established.is_active());
        assert!(ConnectionState::Authenticating.is_active());
        assert!(!ConnectionState::Pending.is_active());
        assert!(ConnectionState::Closed { reason: "done".into() }.is_terminal());
        assert!(ConnectionState::Rejected { reason: "no".into() }.is_terminal());
        assert!(!ConnectionState::Established.is_terminal());
    }
}
