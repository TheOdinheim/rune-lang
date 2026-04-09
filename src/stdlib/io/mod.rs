// ═══════════════════════════════════════════════════════════════════════
// rune::io — File I/O with Effect Enforcement
//
// Every function in this module requires the `io` effect. Calling any
// io operation from RUNE source without declaring `effects { io }` is
// a compile-time type error via the FFI effect system.
//
// These wrap Rust's std::fs via safe APIs. They are the building blocks
// that runeOS will use for governed system calls.
// ═══════════════════════════════════════════════════════════════════════

use std::fs;
use std::io::Write;
use std::path::Path;

// ── Error type ──────────────────────────────────────────────────────

/// Errors from I/O operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoError {
    NotFound(String),
    PermissionDenied(String),
    AlreadyExists(String),
    InvalidPath(String),
    Utf8Error(String),
    Other(String),
}

impl std::fmt::Display for IoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(p) => write!(f, "not found: {p}"),
            Self::PermissionDenied(p) => write!(f, "permission denied: {p}"),
            Self::AlreadyExists(p) => write!(f, "already exists: {p}"),
            Self::InvalidPath(p) => write!(f, "invalid path: {p}"),
            Self::Utf8Error(msg) => write!(f, "UTF-8 error: {msg}"),
            Self::Other(msg) => write!(f, "I/O error: {msg}"),
        }
    }
}

impl std::error::Error for IoError {}

impl From<std::io::Error> for IoError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::NotFound => Self::NotFound(e.to_string()),
            std::io::ErrorKind::PermissionDenied => Self::PermissionDenied(e.to_string()),
            std::io::ErrorKind::AlreadyExists => Self::AlreadyExists(e.to_string()),
            _ => Self::Other(e.to_string()),
        }
    }
}

// ── Effect documentation ────────────────────────────────────────────

/// Documents that all io functions require `effects { io }`.
pub struct IoEffects;

impl IoEffects {
    pub const READ: &'static str = "io";
    pub const WRITE: &'static str = "io";
    pub const DIR: &'static str = "io";
}

// ── File reading ────────────────────────────────────────────────────

/// Read entire file as bytes. Effect: io.
pub fn read_file(path: &str) -> Result<Vec<u8>, IoError> {
    fs::read(path).map_err(IoError::from)
}

/// Read entire file as UTF-8 string. Effect: io.
pub fn read_file_string(path: &str) -> Result<String, IoError> {
    fs::read_to_string(path).map_err(IoError::from)
}

/// Read file as lines. Effect: io.
pub fn read_lines(path: &str) -> Result<Vec<String>, IoError> {
    let content = read_file_string(path)?;
    Ok(content.lines().map(String::from).collect())
}

/// Check if a file exists. Effect: io (checking existence is a side effect).
pub fn file_exists(path: &str) -> bool {
    Path::new(path).exists()
}

// ── File writing ────────────────────────────────────────────────────

/// Write bytes to file (creates or overwrites). Effect: io.
pub fn write_file(path: &str, data: &[u8]) -> Result<(), IoError> {
    fs::write(path, data).map_err(IoError::from)
}

/// Write string to file. Effect: io.
pub fn write_file_string(path: &str, content: &str) -> Result<(), IoError> {
    fs::write(path, content.as_bytes()).map_err(IoError::from)
}

/// Append bytes to file. Effect: io.
pub fn append_file(path: &str, data: &[u8]) -> Result<(), IoError> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(IoError::from)?;
    file.write_all(data).map_err(IoError::from)
}

// ── Directory operations ────────────────────────────────────────────

/// Create directory and parents. Effect: io.
pub fn create_dir(path: &str) -> Result<(), IoError> {
    fs::create_dir_all(path).map_err(IoError::from)
}

/// List directory entries as file names. Effect: io.
pub fn list_dir(path: &str) -> Result<Vec<String>, IoError> {
    let entries = fs::read_dir(path).map_err(IoError::from)?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(IoError::from)?;
        if let Some(name) = entry.file_name().to_str() {
            names.push(name.to_string());
        }
    }
    Ok(names)
}

/// Remove a file. Effect: io.
pub fn remove_file(path: &str) -> Result<(), IoError> {
    fs::remove_file(path).map_err(IoError::from)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("rune_io_tests");
        let _ = fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn test_read_file_existing() {
        let dir = test_dir();
        let path = dir.join("read_test.txt");
        fs::write(&path, b"hello").unwrap();
        let result = read_file(path.to_str().unwrap());
        assert_eq!(result.unwrap(), b"hello");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_read_file_not_found() {
        let result = read_file("/tmp/rune_io_tests/nonexistent_xyzzy.txt");
        assert!(matches!(result, Err(IoError::NotFound(_))));
    }

    #[test]
    fn test_write_then_read_roundtrip() {
        let dir = test_dir();
        let path = dir.join("roundtrip.txt");
        write_file(path.to_str().unwrap(), b"data123").unwrap();
        let data = read_file(path.to_str().unwrap()).unwrap();
        assert_eq!(data, b"data123");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_read_file_string_utf8() {
        let dir = test_dir();
        let path = dir.join("utf8.txt");
        fs::write(&path, "hello world").unwrap();
        let s = read_file_string(path.to_str().unwrap()).unwrap();
        assert_eq!(s, "hello world");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_read_lines() {
        let dir = test_dir();
        let path = dir.join("lines.txt");
        fs::write(&path, "line1\nline2\nline3").unwrap();
        let lines = read_lines(path.to_str().unwrap()).unwrap();
        assert_eq!(lines, vec!["line1", "line2", "line3"]);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_file_exists_true_and_false() {
        let dir = test_dir();
        let path = dir.join("exists_test.txt");
        fs::write(&path, b"x").unwrap();
        assert!(file_exists(path.to_str().unwrap()));
        assert!(!file_exists("/tmp/rune_io_tests/no_such_file_xyzzy.txt"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_append_file() {
        let dir = test_dir();
        let path = dir.join("append.txt");
        write_file(path.to_str().unwrap(), b"first").unwrap();
        append_file(path.to_str().unwrap(), b"_second").unwrap();
        let data = read_file(path.to_str().unwrap()).unwrap();
        assert_eq!(data, b"first_second");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_create_dir_and_list() {
        let dir = test_dir().join("subdir_test");
        let _ = fs::remove_dir_all(&dir);
        create_dir(dir.to_str().unwrap()).unwrap();
        fs::write(dir.join("a.txt"), b"a").unwrap();
        fs::write(dir.join("b.txt"), b"b").unwrap();
        let entries = list_dir(dir.to_str().unwrap()).unwrap();
        assert!(entries.contains(&"a.txt".to_string()));
        assert!(entries.contains(&"b.txt".to_string()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_remove_file_works() {
        let dir = test_dir();
        let path = dir.join("remove_me.txt");
        fs::write(&path, b"x").unwrap();
        assert!(path.exists());
        remove_file(path.to_str().unwrap()).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn test_io_error_display() {
        let err = IoError::NotFound("foo.txt".into());
        assert!(format!("{err}").contains("foo.txt"));
    }

    #[test]
    fn test_io_error_from_std() {
        let std_err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let err: IoError = std_err.into();
        assert!(matches!(err, IoError::NotFound(_)));
    }
}
