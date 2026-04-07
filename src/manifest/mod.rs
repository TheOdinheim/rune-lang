// ═══════════════════════════════════════════════════════════════════════
// RUNE Package Manifest — rune.toml
//
// Defines project metadata, build configuration, and graduation level.
// Every RUNE project has a rune.toml at its root.
// ═══════════════════════════════════════════════════════════════════════

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

#[cfg(test)]
mod tests;

// ── Manifest struct ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuneManifest {
    pub package: PackageSection,
    #[serde(default)]
    pub build: BuildSection,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PackageSection {
    pub name: String,
    pub version: String,
    #[serde(default = "default_edition")]
    pub edition: Option<String>,
    pub description: Option<String>,
    pub authors: Option<Vec<String>>,
    pub license: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BuildSection {
    #[serde(default = "default_target")]
    pub target: Option<String>,
    #[serde(default = "default_optimization")]
    pub optimization: Option<String>,
    #[serde(default = "default_graduation_level")]
    pub graduation_level: Option<String>,
}

fn default_edition() -> Option<String> {
    Some("2026".to_string())
}

fn default_target() -> Option<String> {
    Some("wasm".to_string())
}

fn default_optimization() -> Option<String> {
    Some("debug".to_string())
}

fn default_graduation_level() -> Option<String> {
    Some("bronze".to_string())
}

impl Default for BuildSection {
    fn default() -> Self {
        Self {
            target: default_target(),
            optimization: default_optimization(),
            graduation_level: default_graduation_level(),
        }
    }
}

// ── Error type ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ManifestError {
    IoError(String),
    ParseError(String),
    InvalidName(String),
    InvalidVersion(String),
    InvalidGraduationLevel(String),
    InvalidEdition(String),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestError::IoError(msg) => write!(f, "I/O error: {msg}"),
            ManifestError::ParseError(msg) => write!(f, "parse error: {msg}"),
            ManifestError::InvalidName(msg) => write!(f, "invalid project name: {msg}"),
            ManifestError::InvalidVersion(msg) => write!(f, "invalid version: {msg}"),
            ManifestError::InvalidGraduationLevel(msg) => {
                write!(f, "invalid graduation level: {msg}")
            }
            ManifestError::InvalidEdition(msg) => write!(f, "invalid edition: {msg}"),
        }
    }
}

// ── Methods ─────────────────────────────────────────────────────────

impl RuneManifest {
    pub fn from_file(path: &Path) -> Result<Self, ManifestError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| ManifestError::IoError(e.to_string()))?;
        Self::from_str(&content)
    }

    pub fn from_str(content: &str) -> Result<Self, ManifestError> {
        let manifest: RuneManifest =
            toml::from_str(content).map_err(|e| ManifestError::ParseError(e.to_string()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn default_new(name: &str) -> Self {
        Self {
            package: PackageSection {
                name: name.to_string(),
                version: "0.1.0".to_string(),
                edition: Some("2026".to_string()),
                description: None,
                authors: None,
                license: None,
            },
            build: BuildSection::default(),
        }
    }

    pub fn to_toml_string(&self) -> String {
        toml::to_string_pretty(self).expect("manifest should be serializable")
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        validate_name(&self.package.name)?;
        validate_version(&self.package.version)?;

        if let Some(ref edition) = self.package.edition {
            validate_edition(edition)?;
        }

        if let Some(ref level) = self.build.graduation_level {
            validate_graduation_level(level)?;
        }

        Ok(())
    }
}

// ── Validation helpers ──────────────────────────────────────────────

fn validate_name(name: &str) -> Result<(), ManifestError> {
    if name.is_empty() {
        return Err(ManifestError::InvalidName(
            "name must not be empty".to_string(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(ManifestError::InvalidName(format!(
            "'{name}' must contain only lowercase letters, digits, hyphens, and underscores"
        )));
    }
    if !name.chars().next().unwrap().is_ascii_lowercase() {
        return Err(ManifestError::InvalidName(format!(
            "'{name}' must start with a lowercase letter"
        )));
    }
    Ok(())
}

fn validate_version(version: &str) -> Result<(), ManifestError> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 {
        return Err(ManifestError::InvalidVersion(format!(
            "'{version}' is not valid semver (expected MAJOR.MINOR.PATCH)"
        )));
    }
    for part in &parts {
        if part.parse::<u64>().is_err() {
            return Err(ManifestError::InvalidVersion(format!(
                "'{version}' is not valid semver (non-numeric component)"
            )));
        }
    }
    Ok(())
}

fn validate_edition(edition: &str) -> Result<(), ManifestError> {
    if edition.parse::<u32>().is_err() || edition.len() != 4 {
        return Err(ManifestError::InvalidEdition(format!(
            "'{edition}' is not a valid edition (expected a 4-digit year, e.g. \"2026\")"
        )));
    }
    Ok(())
}

fn validate_graduation_level(level: &str) -> Result<(), ManifestError> {
    match level {
        "bronze" | "silver" | "gold" | "platinum" => Ok(()),
        _ => Err(ManifestError::InvalidGraduationLevel(format!(
            "'{level}' is not valid (expected bronze, silver, gold, or platinum)"
        ))),
    }
}
