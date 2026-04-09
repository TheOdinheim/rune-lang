// ═══════════════════════════════════════════════════════════════════════
// rune::env — Environment Access with Effect Enforcement
//
// Every function requires the `io` effect (environment is external state).
// Reading env vars, hostname, and cwd are all observable side effects.
// ═══════════════════════════════════════════════════════════════════════

use crate::stdlib::io::IoError;

// ── Effect documentation ────────────────────────────────────────────

pub struct EnvEffects;

impl EnvEffects {
    pub const ENV: &'static str = "io";
    pub const SYSTEM: &'static str = "io";
}

// ── Environment variables ───────────────────────────────────────────

/// Get an environment variable. Effect: io.
pub fn get_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// Get an environment variable with a default fallback. Effect: io.
pub fn get_env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

/// List all environment variables. Effect: io.
pub fn env_vars() -> Vec<(String, String)> {
    std::env::vars().collect()
}

// ── System info ─────────────────────────────────────────────────────

/// Get the system hostname. Effect: io.
pub fn hostname() -> Result<String, IoError> {
    // Read from /etc/hostname on Linux, or use the hostname command.
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .or_else(|_| {
            std::process::Command::new("hostname")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .map_err(|e| IoError::Other(e.to_string()))
        })
}

/// Get the current working directory. Effect: io.
pub fn current_dir() -> Result<String, IoError> {
    std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| IoError::Other(e.to_string()))
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_env_path() {
        // PATH is always set on Unix systems.
        assert!(get_env("PATH").is_some());
    }

    #[test]
    fn test_get_env_nonexistent() {
        assert!(get_env("RUNE_NONEXISTENT_VAR_XYZZY_12345").is_none());
    }

    #[test]
    fn test_get_env_or_default() {
        let val = get_env_or("RUNE_NONEXISTENT_VAR_XYZZY_12345", "fallback");
        assert_eq!(val, "fallback");
    }

    #[test]
    fn test_env_vars_non_empty() {
        let vars = env_vars();
        assert!(!vars.is_empty());
    }

    #[test]
    fn test_hostname_non_empty() {
        let name = hostname().unwrap();
        assert!(!name.is_empty());
    }

    #[test]
    fn test_current_dir_non_empty() {
        let dir = current_dir().unwrap();
        assert!(!dir.is_empty());
    }
}
