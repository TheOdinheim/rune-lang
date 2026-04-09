// ═══════════════════════════════════════════════════════════════════════
// RUNE Edition System
//
// Each edition defines which language features are available. Older
// editions continue to compile unchanged as the language evolves.
// This is a binding architectural commitment (see RUNE_05 Section 14.5).
//
// Pillar: No Single Points of Failure — old policy code never stops
// compiling. Governance rules written in edition 2026 compile correctly
// in 2028, 2030, and beyond.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

/// A RUNE language edition.
///
/// Each edition represents a stable snapshot of the language syntax and
/// semantics. Code written for a given edition will always compile under
/// that edition's rules, even as new editions are released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edition {
    /// Edition 2026: the initial stable edition. Includes all M1–M7 features.
    Edition2026,
}

impl Edition {
    /// Parse an edition string (e.g., "2026") into an Edition.
    pub fn from_str(s: &str) -> Result<Edition, String> {
        match s {
            "2026" => Ok(Edition::Edition2026),
            _ => Err(format!(
                "unknown edition '{}' — supported editions: 2026",
                s,
            )),
        }
    }
}

impl Default for Edition {
    fn default() -> Self {
        Edition::Edition2026
    }
}

impl fmt::Display for Edition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Edition::Edition2026 => write!(f, "2026"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edition_from_str_2026() {
        assert_eq!(Edition::from_str("2026"), Ok(Edition::Edition2026));
    }

    #[test]
    fn test_edition_from_str_unknown() {
        let result = Edition::from_str("2028");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown edition"));
    }

    #[test]
    fn test_edition_default() {
        assert_eq!(Edition::default(), Edition::Edition2026);
    }

    #[test]
    fn test_edition_display() {
        assert_eq!(format!("{}", Edition::Edition2026), "2026");
    }
}
