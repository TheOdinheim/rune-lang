// ═══════════════════════════════════════════════════════════════════════
// Module file resolver and loader for multi-file RUNE compilation.
//
// Handles the `mod name;` file-based module syntax by resolving module
// names to file paths (following Rust conventions) and loading their
// source code. Detects circular dependencies and ambiguous module paths.
//
// Pillar: Assumed Breach — cycle detection prevents infinite loops from
// malicious or accidental circular imports.
// Pillar: Zero Trust — every module file is independently parsed and
// type-checked; no implicit trust across file boundaries.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

// ── Error types ──────────────────────────────────────────────────────

/// Errors that can occur during module file resolution and loading.
#[derive(Debug, Clone)]
pub enum ModuleLoadError {
    /// Neither `module_name.rune` nor `module_name/mod.rune` found.
    FileNotFound {
        module_name: String,
        expected_paths: Vec<PathBuf>,
    },
    /// Both `module_name.rune` and `module_name/mod.rune` exist.
    AmbiguousModule {
        module_name: String,
        path_a: PathBuf,
        path_b: PathBuf,
    },
    /// Circular module dependency detected.
    CircularDependency {
        cycle: Vec<PathBuf>,
    },
    /// Filesystem I/O error.
    IoError {
        path: PathBuf,
        error: String,
    },
}

impl fmt::Display for ModuleLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ModuleLoadError::FileNotFound { module_name, expected_paths } => {
                let paths: Vec<String> = expected_paths.iter()
                    .map(|p| p.display().to_string())
                    .collect();
                write!(
                    f,
                    "file not found for module `{}` — expected {}",
                    module_name,
                    paths.join(" or "),
                )
            }
            ModuleLoadError::AmbiguousModule { module_name, path_a, path_b } => {
                write!(
                    f,
                    "ambiguous module `{}` — both {} and {} exist",
                    module_name,
                    path_a.display(),
                    path_b.display(),
                )
            }
            ModuleLoadError::CircularDependency { cycle } => {
                let chain: Vec<String> = cycle.iter()
                    .map(|p| p.display().to_string())
                    .collect();
                write!(f, "circular module dependency: {}", chain.join(" -> "))
            }
            ModuleLoadError::IoError { path, error } => {
                write!(f, "cannot read {}: {}", path.display(), error)
            }
        }
    }
}

impl std::error::Error for ModuleLoadError {}

// ── Module loader ────────────────────────────────────────────────────

/// Resolves module names to file paths and loads their source code.
///
/// Follows Rust conventions:
/// - `mod crypto;` looks for `crypto.rune` (sibling) or `crypto/mod.rune` (directory)
/// - If both exist, it's an error (ambiguous)
/// - Circular dependencies are detected via a loading stack
pub struct ModuleLoader {
    /// Cache of already-loaded file contents.
    loaded_files: HashMap<PathBuf, String>,
    /// Files currently being loaded (for cycle detection).
    loading_stack: Vec<PathBuf>,
    /// Monotonically increasing file ID counter for span tracking.
    next_file_id: u32,
    /// Map from file ID to file path (for error reporting).
    pub file_paths: HashMap<u32, PathBuf>,
}

impl ModuleLoader {
    /// Create a new module loader.
    ///
    /// `root_file_id` is the file ID assigned to the root source file.
    /// Module files get incrementing IDs starting from `root_file_id + 1`.
    pub fn new(root_file: &Path, root_file_id: u32) -> Self {
        let mut file_paths = HashMap::new();
        file_paths.insert(root_file_id, root_file.to_path_buf());
        Self {
            loaded_files: HashMap::new(),
            loading_stack: vec![root_file.to_path_buf()],
            next_file_id: root_file_id + 1,
            file_paths,
        }
    }

    /// Resolve a module name to its source file path.
    ///
    /// Given the parent file's path and a module name, searches for:
    /// 1. `parent_dir/module_name.rune` (sibling file)
    /// 2. `parent_dir/module_name/mod.rune` (directory module)
    pub fn resolve_module_path(
        &self,
        parent_file: &Path,
        module_name: &str,
    ) -> Result<PathBuf, ModuleLoadError> {
        let parent_dir = parent_file.parent().unwrap_or_else(|| Path::new("."));

        let sibling = parent_dir.join(format!("{}.rune", module_name));
        let dir_mod = parent_dir.join(module_name).join("mod.rune");

        let sibling_exists = sibling.exists();
        let dir_mod_exists = dir_mod.exists();

        match (sibling_exists, dir_mod_exists) {
            (true, true) => Err(ModuleLoadError::AmbiguousModule {
                module_name: module_name.to_string(),
                path_a: sibling,
                path_b: dir_mod,
            }),
            (true, false) => Ok(sibling),
            (false, true) => Ok(dir_mod),
            (false, false) => Err(ModuleLoadError::FileNotFound {
                module_name: module_name.to_string(),
                expected_paths: vec![sibling, dir_mod],
            }),
        }
    }

    /// Load a module's source code from disk.
    ///
    /// Resolves the path, checks for circular dependencies, reads the file,
    /// and returns the source code, resolved path, and assigned file ID.
    pub fn load_module(
        &mut self,
        parent_file: &Path,
        module_name: &str,
    ) -> Result<(String, PathBuf, u32), ModuleLoadError> {
        let resolved = self.resolve_module_path(parent_file, module_name)?;
        let canonical = resolved.canonicalize().unwrap_or_else(|_| resolved.clone());

        // Check for circular dependencies.
        if self.loading_stack.iter().any(|p| {
            p.canonicalize().unwrap_or_else(|_| p.clone()) == canonical
        }) {
            let mut cycle = self.loading_stack.clone();
            cycle.push(resolved.clone());
            return Err(ModuleLoadError::CircularDependency { cycle });
        }

        // Return from cache if already loaded.
        if let Some(source) = self.loaded_files.get(&canonical) {
            let file_id = self.next_file_id;
            self.next_file_id += 1;
            self.file_paths.insert(file_id, resolved.clone());
            return Ok((source.clone(), resolved, file_id));
        }

        // Read the file.
        let source = std::fs::read_to_string(&resolved).map_err(|e| {
            ModuleLoadError::IoError {
                path: resolved.clone(),
                error: e.to_string(),
            }
        })?;

        // Cache the contents.
        self.loaded_files.insert(canonical, source.clone());

        // Assign a file ID.
        let file_id = self.next_file_id;
        self.next_file_id += 1;
        self.file_paths.insert(file_id, resolved.clone());

        Ok((source, resolved, file_id))
    }

    /// Push a file onto the loading stack (call before processing a module file).
    pub fn push_loading(&mut self, path: &Path) {
        self.loading_stack.push(path.to_path_buf());
    }

    /// Pop a file from the loading stack (call after processing a module file).
    pub fn pop_loading(&mut self) {
        self.loading_stack.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn create_temp_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "rune_loader_{}_{}", std::process::id(), n
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_resolve_sibling_file() {
        let dir = create_temp_dir();
        let parent = dir.join("main.rune");
        fs::write(&parent, "").unwrap();
        fs::write(dir.join("crypto.rune"), "pub fn verify() -> Bool { true }").unwrap();

        let loader = ModuleLoader::new(&parent, 0);
        let result = loader.resolve_module_path(&parent, "crypto");
        assert!(result.is_ok());
        assert!(result.unwrap().ends_with("crypto.rune"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_resolve_directory_mod_file() {
        let dir = create_temp_dir();
        let parent = dir.join("main.rune");
        fs::write(&parent, "").unwrap();
        let crypto_dir = dir.join("crypto");
        fs::create_dir_all(&crypto_dir).unwrap();
        fs::write(crypto_dir.join("mod.rune"), "pub fn verify() -> Bool { true }").unwrap();

        let loader = ModuleLoader::new(&parent, 0);
        let result = loader.resolve_module_path(&parent, "crypto");
        assert!(result.is_ok());
        assert!(result.unwrap().ends_with("mod.rune"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_resolve_not_found() {
        let dir = create_temp_dir();
        let parent = dir.join("main.rune");
        fs::write(&parent, "").unwrap();

        let loader = ModuleLoader::new(&parent, 0);
        let result = loader.resolve_module_path(&parent, "nonexistent");
        assert!(matches!(result, Err(ModuleLoadError::FileNotFound { .. })));
        let err = result.unwrap_err();
        assert!(err.to_string().contains("file not found"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_resolve_ambiguous() {
        let dir = create_temp_dir();
        let parent = dir.join("main.rune");
        fs::write(&parent, "").unwrap();
        fs::write(dir.join("crypto.rune"), "").unwrap();
        let crypto_dir = dir.join("crypto");
        fs::create_dir_all(&crypto_dir).unwrap();
        fs::write(crypto_dir.join("mod.rune"), "").unwrap();

        let loader = ModuleLoader::new(&parent, 0);
        let result = loader.resolve_module_path(&parent, "crypto");
        assert!(matches!(result, Err(ModuleLoadError::AmbiguousModule { .. })));
        let err = result.unwrap_err();
        assert!(err.to_string().contains("ambiguous"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_module_returns_source() {
        let dir = create_temp_dir();
        let parent = dir.join("main.rune");
        fs::write(&parent, "").unwrap();
        fs::write(dir.join("crypto.rune"), "pub fn verify() -> Bool { true }").unwrap();

        let mut loader = ModuleLoader::new(&parent, 0);
        let result = loader.load_module(&parent, "crypto");
        assert!(result.is_ok());
        let (source, path, file_id) = result.unwrap();
        assert!(source.contains("verify"));
        assert!(path.ends_with("crypto.rune"));
        assert_eq!(file_id, 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_circular_dependency_detection() {
        let dir = create_temp_dir();
        let a = dir.join("a.rune");
        let b = dir.join("b.rune");
        fs::write(&a, "mod b;").unwrap();
        fs::write(&b, "mod a;").unwrap();

        let mut loader = ModuleLoader::new(&a, 0);
        // Simulate: a is loading, now try to load a again from b's context.
        loader.push_loading(&b);
        let result = loader.load_module(&b, "a");
        assert!(matches!(result, Err(ModuleLoadError::CircularDependency { .. })));
        let err = result.unwrap_err();
        assert!(err.to_string().contains("circular"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_io_error_on_unreadable() {
        let dir = create_temp_dir();
        let parent = dir.join("main.rune");
        fs::write(&parent, "").unwrap();
        // Create a directory where a file is expected — reading it will fail.
        fs::create_dir_all(dir.join("broken.rune")).unwrap();

        let mut loader = ModuleLoader::new(&parent, 0);
        let result = loader.load_module(&parent, "broken");
        // Should be IoError because broken.rune is a directory, not a file.
        assert!(matches!(result, Err(ModuleLoadError::IoError { .. })));

        let _ = fs::remove_dir_all(&dir);
    }
}
