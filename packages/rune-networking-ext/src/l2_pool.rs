// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Connection pool governance.
//
// Governed connection pools with max capacity, idle/lifetime eviction,
// utilization tracking, and audit trail.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::NetworkError;

// ── L2ConnectionState ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L2ConnectionState {
    Active,
    Idle,
    Draining,
    Closed,
}

impl fmt::Display for L2ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Idle => write!(f, "Idle"),
            Self::Draining => write!(f, "Draining"),
            Self::Closed => write!(f, "Closed"),
        }
    }
}

// ── PooledConnection ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PooledConnection {
    pub id: String,
    pub target: String,
    pub state: L2ConnectionState,
    pub created_at: i64,
    pub last_used_at: i64,
    pub use_count: u64,
}

// ── PoolStats ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PoolStats {
    pub active: usize,
    pub idle: usize,
    pub total_created: u64,
    pub total_closed: u64,
    pub utilization: f64,
    pub oldest_connection_age_ms: Option<i64>,
}

// ── GovernedConnectionPool ───────────────────────────────────────

#[derive(Debug)]
pub struct GovernedConnectionPool {
    pub pool_id: String,
    connections: HashMap<String, PooledConnection>,
    max_connections: usize,
    max_idle_ms: i64,
    max_lifetime_ms: i64,
    total_created: u64,
    total_closed: u64,
}

impl GovernedConnectionPool {
    pub fn new(pool_id: &str, max_connections: usize, max_idle_ms: i64, max_lifetime_ms: i64) -> Self {
        Self {
            pool_id: pool_id.into(),
            connections: HashMap::new(),
            max_connections,
            max_idle_ms,
            max_lifetime_ms,
            total_created: 0,
            total_closed: 0,
        }
    }

    pub fn acquire(
        &mut self,
        connection_id: &str,
        target: &str,
        now: i64,
    ) -> Result<&PooledConnection, NetworkError> {
        let non_closed = self
            .connections
            .values()
            .filter(|c| c.state != L2ConnectionState::Closed)
            .count();

        if non_closed >= self.max_connections {
            return Err(NetworkError::ConnectionLimitReached {
                max: self.max_connections,
            });
        }

        self.total_created += 1;
        self.connections.insert(
            connection_id.to_string(),
            PooledConnection {
                id: connection_id.to_string(),
                target: target.to_string(),
                state: L2ConnectionState::Active,
                created_at: now,
                last_used_at: now,
                use_count: 1,
            },
        );
        Ok(self.connections.get(connection_id).unwrap())
    }

    pub fn release(&mut self, connection_id: &str, now: i64) -> bool {
        if let Some(conn) = self.connections.get_mut(connection_id) {
            if conn.state == L2ConnectionState::Active {
                conn.state = L2ConnectionState::Idle;
                conn.last_used_at = now;
                return true;
            }
        }
        false
    }

    pub fn close(&mut self, connection_id: &str, _now: i64) -> bool {
        if let Some(conn) = self.connections.get_mut(connection_id) {
            if conn.state != L2ConnectionState::Closed {
                conn.state = L2ConnectionState::Closed;
                self.total_closed += 1;
                return true;
            }
        }
        false
    }

    pub fn evict_idle(&mut self, now: i64) -> usize {
        let to_evict: Vec<String> = self
            .connections
            .iter()
            .filter(|(_, c)| {
                c.state == L2ConnectionState::Idle
                    && (now - c.last_used_at) > self.max_idle_ms
            })
            .map(|(id, _)| id.clone())
            .collect();
        let count = to_evict.len();
        for id in &to_evict {
            if let Some(conn) = self.connections.get_mut(id) {
                conn.state = L2ConnectionState::Closed;
                self.total_closed += 1;
            }
        }
        count
    }

    pub fn evict_expired(&mut self, now: i64) -> usize {
        let to_evict: Vec<String> = self
            .connections
            .iter()
            .filter(|(_, c)| {
                c.state != L2ConnectionState::Closed
                    && (now - c.created_at) > self.max_lifetime_ms
            })
            .map(|(id, _)| id.clone())
            .collect();
        let count = to_evict.len();
        for id in &to_evict {
            if let Some(conn) = self.connections.get_mut(id) {
                conn.state = L2ConnectionState::Closed;
                self.total_closed += 1;
            }
        }
        count
    }

    pub fn active_count(&self) -> usize {
        self.connections
            .values()
            .filter(|c| c.state == L2ConnectionState::Active)
            .count()
    }

    pub fn idle_count(&self) -> usize {
        self.connections
            .values()
            .filter(|c| c.state == L2ConnectionState::Idle)
            .count()
    }

    pub fn utilization(&self) -> f64 {
        if self.max_connections == 0 {
            return 0.0;
        }
        self.active_count() as f64 / self.max_connections as f64
    }

    pub fn pool_stats(&self, now: i64) -> PoolStats {
        let oldest_age = self
            .connections
            .values()
            .filter(|c| c.state != L2ConnectionState::Closed)
            .map(|c| now - c.created_at)
            .max();

        PoolStats {
            active: self.active_count(),
            idle: self.idle_count(),
            total_created: self.total_created,
            total_closed: self.total_closed,
            utilization: self.utilization(),
            oldest_connection_age_ms: oldest_age,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acquire_creates_connection() {
        let mut pool = GovernedConnectionPool::new("pool-1", 10, 30_000, 300_000);
        let conn = pool.acquire("c1", "db.example.com:5432", 1000).unwrap();
        assert_eq!(conn.state, L2ConnectionState::Active);
        assert_eq!(conn.target, "db.example.com:5432");
    }

    #[test]
    fn test_acquire_fails_at_max_capacity() {
        let mut pool = GovernedConnectionPool::new("pool-1", 1, 30_000, 300_000);
        pool.acquire("c1", "target", 1000).unwrap();
        let result = pool.acquire("c2", "target", 1001);
        assert!(result.is_err());
    }

    #[test]
    fn test_release_sets_idle() {
        let mut pool = GovernedConnectionPool::new("pool-1", 10, 30_000, 300_000);
        pool.acquire("c1", "target", 1000).unwrap();
        assert!(pool.release("c1", 2000));
        assert_eq!(pool.idle_count(), 1);
        assert_eq!(pool.active_count(), 0);
    }

    #[test]
    fn test_evict_idle_removes_old_idle() {
        let mut pool = GovernedConnectionPool::new("pool-1", 10, 5_000, 300_000);
        pool.acquire("c1", "target", 1000).unwrap();
        pool.release("c1", 2000);
        // 10_000 - 2000 = 8_000 > 5_000 max_idle
        let evicted = pool.evict_idle(10_000);
        assert_eq!(evicted, 1);
    }

    #[test]
    fn test_evict_expired_removes_old_connections() {
        let mut pool = GovernedConnectionPool::new("pool-1", 10, 30_000, 5_000);
        pool.acquire("c1", "target", 1000).unwrap();
        // 10_000 - 1000 = 9_000 > 5_000 max_lifetime
        let evicted = pool.evict_expired(10_000);
        assert_eq!(evicted, 1);
    }

    #[test]
    fn test_utilization_calculates_correctly() {
        let mut pool = GovernedConnectionPool::new("pool-1", 4, 30_000, 300_000);
        pool.acquire("c1", "target", 1000).unwrap();
        pool.acquire("c2", "target", 1000).unwrap();
        assert!((pool.utilization() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pool_stats_returns_accurate() {
        let mut pool = GovernedConnectionPool::new("pool-1", 10, 30_000, 300_000);
        pool.acquire("c1", "target", 1000).unwrap();
        pool.acquire("c2", "target", 2000).unwrap();
        pool.release("c2", 3000);
        let stats = pool.pool_stats(5000);
        assert_eq!(stats.active, 1);
        assert_eq!(stats.idle, 1);
        assert_eq!(stats.total_created, 2);
        assert_eq!(stats.total_closed, 0);
    }

    #[test]
    fn test_close_removes_connection() {
        let mut pool = GovernedConnectionPool::new("pool-1", 10, 30_000, 300_000);
        pool.acquire("c1", "target", 1000).unwrap();
        assert!(pool.close("c1", 2000));
        assert_eq!(pool.active_count(), 0);
        assert_eq!(pool.pool_stats(3000).total_closed, 1);
    }
}
