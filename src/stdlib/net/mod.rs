// ═══════════════════════════════════════════════════════════════════════
// rune::net — Networking with Effect Enforcement
//
// Every network function requires the `network` effect. Calling any
// network operation from RUNE source without declaring `effects { network }`
// is a compile-time type error.
//
// Minimal TCP-level API. Full HTTP support is a future enhancement.
// parse_url is pure computation (no effect required).
// ═══════════════════════════════════════════════════════════════════════

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

// ── Error type ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetError {
    ConnectionRefused(String),
    ConnectionTimeout(String),
    DnsResolutionFailed(String),
    InvalidUrl(String),
    IoError(String),
    Other(String),
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionRefused(msg) => write!(f, "connection refused: {msg}"),
            Self::ConnectionTimeout(msg) => write!(f, "connection timeout: {msg}"),
            Self::DnsResolutionFailed(msg) => write!(f, "DNS resolution failed: {msg}"),
            Self::InvalidUrl(msg) => write!(f, "invalid URL: {msg}"),
            Self::IoError(msg) => write!(f, "network I/O error: {msg}"),
            Self::Other(msg) => write!(f, "network error: {msg}"),
        }
    }
}

impl std::error::Error for NetError {}

// ── Effect documentation ────────────────────────────────────────────

pub struct NetEffects;

impl NetEffects {
    pub const TCP: &'static str = "network";
    pub const DNS: &'static str = "network";
}

// ── Connection ID generator ─────────────────────────────────────────

static CONN_ID: AtomicU64 = AtomicU64::new(1);

fn next_conn_id() -> u64 {
    CONN_ID.fetch_add(1, Ordering::Relaxed)
}

// ── TCP connection ──────────────────────────────────────────────────

/// A TCP connection with audit tracking metadata.
pub struct TcpConnection {
    stream: TcpStream,
    pub connection_id: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Connect to a TCP host:port with a 5-second timeout. Effect: network.
pub fn tcp_connect(host: &str, port: u16) -> Result<TcpConnection, NetError> {
    let addr = format!("{host}:{port}");
    let stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| NetError::DnsResolutionFailed(format!("{e}")))?,
        Duration::from_secs(5),
    )
    .map_err(|e| match e.kind() {
        std::io::ErrorKind::ConnectionRefused => {
            NetError::ConnectionRefused(addr.clone())
        }
        std::io::ErrorKind::TimedOut => NetError::ConnectionTimeout(addr.clone()),
        _ => NetError::IoError(e.to_string()),
    })?;

    Ok(TcpConnection {
        stream,
        connection_id: next_conn_id(),
        bytes_sent: 0,
        bytes_received: 0,
    })
}

/// Send data on a connection. Effect: network.
pub fn tcp_send(conn: &mut TcpConnection, data: &[u8]) -> Result<usize, NetError> {
    conn.stream
        .write(data)
        .map(|n| {
            conn.bytes_sent += n as u64;
            n
        })
        .map_err(|e| NetError::IoError(e.to_string()))
}

/// Receive data from a connection. Effect: network.
pub fn tcp_receive(conn: &mut TcpConnection, max_bytes: usize) -> Result<Vec<u8>, NetError> {
    let mut buf = vec![0u8; max_bytes];
    let n = conn
        .stream
        .read(&mut buf)
        .map_err(|e| NetError::IoError(e.to_string()))?;
    conn.bytes_received += n as u64;
    buf.truncate(n);
    Ok(buf)
}

/// Close a connection. Effect: network.
pub fn tcp_close(conn: TcpConnection) -> Result<(), NetError> {
    conn.stream
        .shutdown(std::net::Shutdown::Both)
        .map_err(|e| NetError::IoError(e.to_string()))
}

// ── DNS resolution ──────────────────────────────────────────────────

/// Resolve a hostname to IP addresses. Effect: network.
pub fn resolve_host(hostname: &str) -> Result<Vec<String>, NetError> {
    use std::net::ToSocketAddrs;
    let addr = format!("{hostname}:0");
    let addrs = addr
        .to_socket_addrs()
        .map_err(|e| NetError::DnsResolutionFailed(format!("{hostname}: {e}")))?;
    Ok(addrs.map(|a| a.ip().to_string()).collect())
}

// ── URL parsing (pure — no effect required) ─────────────────────────

/// Parsed URL components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlParts {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
}

/// Parse a URL into components. Pure computation — no effect required.
pub fn parse_url(url: &str) -> Result<UrlParts, NetError> {
    // scheme://host[:port][/path]
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| NetError::InvalidUrl("missing scheme (expected scheme://...)".into()))?;

    if rest.is_empty() {
        return Err(NetError::InvalidUrl("missing host".into()));
    }

    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), Some(port)),
            Err(_) => (authority.to_string(), None),
        },
        None => (authority.to_string(), None),
    };

    if host.is_empty() {
        return Err(NetError::InvalidUrl("empty host".into()));
    }

    Ok(UrlParts {
        scheme: scheme.to_string(),
        host,
        port,
        path: path.to_string(),
    })
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_url_full() {
        let parts = parse_url("https://example.com:443/api/v1").unwrap();
        assert_eq!(parts.scheme, "https");
        assert_eq!(parts.host, "example.com");
        assert_eq!(parts.port, Some(443));
        assert_eq!(parts.path, "/api/v1");
    }

    #[test]
    fn test_parse_url_no_port() {
        let parts = parse_url("http://example.com/path").unwrap();
        assert_eq!(parts.host, "example.com");
        assert_eq!(parts.port, None);
        assert_eq!(parts.path, "/path");
    }

    #[test]
    fn test_parse_url_no_path() {
        let parts = parse_url("https://example.com").unwrap();
        assert_eq!(parts.path, "/");
    }

    #[test]
    fn test_parse_url_invalid_no_scheme() {
        let result = parse_url("example.com/path");
        assert!(matches!(result, Err(NetError::InvalidUrl(_))));
    }

    #[test]
    fn test_parse_url_empty_host() {
        let result = parse_url("http:///path");
        assert!(matches!(result, Err(NetError::InvalidUrl(_))));
    }

    #[test]
    fn test_connection_id_unique() {
        let id1 = next_conn_id();
        let id2 = next_conn_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_net_error_display() {
        let err = NetError::ConnectionRefused("localhost:9999".into());
        assert!(format!("{err}").contains("localhost:9999"));
    }

    #[test]
    fn test_tcp_connect_invalid_host() {
        // Connecting to a non-routable address should error, not panic.
        let result = tcp_connect("192.0.2.1", 1);
        assert!(result.is_err());
    }

    #[test]
    #[ignore] // environment-dependent
    fn test_resolve_host_localhost() {
        let addrs = resolve_host("localhost").unwrap();
        assert!(!addrs.is_empty());
    }
}
