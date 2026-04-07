#[cfg(test)]
mod tests {
    use crate::manifest::*;
    use std::path::Path;

    #[test]
    fn test_parse_full_manifest() {
        let toml = r#"
[package]
name = "my-policy"
version = "1.2.3"
edition = "2026"
description = "An AI governance policy"
authors = ["Alice <alice@example.com>"]
license = "MIT"

[build]
target = "wasm"
optimization = "release"
graduation_level = "silver"
"#;
        let manifest = RuneManifest::from_str(toml).unwrap();
        assert_eq!(manifest.package.name, "my-policy");
        assert_eq!(manifest.package.version, "1.2.3");
        assert_eq!(manifest.package.edition, Some("2026".to_string()));
        assert_eq!(
            manifest.package.description,
            Some("An AI governance policy".to_string())
        );
        assert_eq!(
            manifest.package.authors,
            Some(vec!["Alice <alice@example.com>".to_string()])
        );
        assert_eq!(manifest.package.license, Some("MIT".to_string()));
        assert_eq!(manifest.build.target, Some("wasm".to_string()));
        assert_eq!(manifest.build.optimization, Some("release".to_string()));
        assert_eq!(
            manifest.build.graduation_level,
            Some("silver".to_string())
        );
    }

    #[test]
    fn test_parse_minimal_manifest() {
        let toml = r#"
[package]
name = "minimal"
version = "0.1.0"
"#;
        let manifest = RuneManifest::from_str(toml).unwrap();
        assert_eq!(manifest.package.name, "minimal");
        assert_eq!(manifest.package.version, "0.1.0");
        // Defaults applied.
        assert_eq!(manifest.package.edition, Some("2026".to_string()));
        assert_eq!(manifest.build.target, Some("wasm".to_string()));
        assert_eq!(manifest.build.optimization, Some("debug".to_string()));
        assert_eq!(
            manifest.build.graduation_level,
            Some("bronze".to_string())
        );
    }

    #[test]
    fn test_default_new_has_correct_values() {
        let manifest = RuneManifest::default_new("test-project");
        assert_eq!(manifest.package.name, "test-project");
        assert_eq!(manifest.package.version, "0.1.0");
        assert_eq!(manifest.package.edition, Some("2026".to_string()));
        assert_eq!(manifest.build.target, Some("wasm".to_string()));
        assert_eq!(manifest.build.optimization, Some("debug".to_string()));
        assert_eq!(
            manifest.build.graduation_level,
            Some("bronze".to_string())
        );
    }

    #[test]
    fn test_invalid_name_uppercase() {
        let toml = r#"
[package]
name = "MyProject"
version = "0.1.0"
"#;
        let err = RuneManifest::from_str(toml).unwrap_err();
        assert!(matches!(err, ManifestError::InvalidName(_)));
    }

    #[test]
    fn test_invalid_name_spaces() {
        let toml = r#"
[package]
name = "my project"
version = "0.1.0"
"#;
        let err = RuneManifest::from_str(toml).unwrap_err();
        assert!(matches!(err, ManifestError::InvalidName(_)));
    }

    #[test]
    fn test_invalid_name_starts_with_digit() {
        let toml = r#"
[package]
name = "1project"
version = "0.1.0"
"#;
        let err = RuneManifest::from_str(toml).unwrap_err();
        assert!(matches!(err, ManifestError::InvalidName(_)));
    }

    #[test]
    fn test_invalid_graduation_level() {
        let toml = r#"
[package]
name = "test"
version = "0.1.0"

[build]
graduation_level = "diamond"
"#;
        let err = RuneManifest::from_str(toml).unwrap_err();
        assert!(matches!(err, ManifestError::InvalidGraduationLevel(_)));
    }

    #[test]
    fn test_invalid_version() {
        let toml = r#"
[package]
name = "test"
version = "not-semver"
"#;
        let err = RuneManifest::from_str(toml).unwrap_err();
        assert!(matches!(err, ManifestError::InvalidVersion(_)));
    }

    #[test]
    fn test_round_trip() {
        let original = RuneManifest::default_new("round-trip");
        let toml_str = original.to_toml_string();
        let parsed = RuneManifest::from_str(&toml_str).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_from_file_nonexistent_returns_io_error() {
        let err = RuneManifest::from_file(Path::new("/nonexistent/rune.toml")).unwrap_err();
        assert!(matches!(err, ManifestError::IoError(_)));
    }

    #[test]
    fn test_validate_catches_empty_name() {
        let manifest = RuneManifest {
            package: PackageSection {
                name: "".to_string(),
                version: "0.1.0".to_string(),
                edition: Some("2026".to_string()),
                description: None,
                authors: None,
                license: None,
            },
            build: BuildSection::default(),
        };
        let err = manifest.validate().unwrap_err();
        assert!(matches!(err, ManifestError::InvalidName(_)));
    }

    #[test]
    fn test_invalid_edition() {
        let toml = r#"
[package]
name = "test"
version = "0.1.0"
edition = "abc"
"#;
        let err = RuneManifest::from_str(toml).unwrap_err();
        assert!(matches!(err, ManifestError::InvalidEdition(_)));
    }
}
