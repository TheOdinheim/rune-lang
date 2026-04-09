use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn rune_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rune-lang"))
}

fn write_temp(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("rune_cli_tests");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    fs::write(&path, content).unwrap();
    path
}

fn temp_project_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("rune_cli_tests").join(name);
    // Clean up from previous test run.
    let _ = fs::remove_dir_all(&dir);
    dir
}

#[test]
fn test_cli_check_valid_source_exits_0() {
    let path = write_temp("check_valid.rune", "policy access { rule allow() { permit } }");
    let output = rune_bin().args(["check", path.to_str().unwrap()]).output().unwrap();
    assert!(output.status.success(), "exit code: {}", output.status);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no errors"), "stderr: {stderr}");
}

#[test]
fn test_cli_check_invalid_source_exits_1() {
    let path = write_temp("check_invalid.rune", "fn bad( { }");
    let output = rune_bin().args(["check", path.to_str().unwrap()]).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error"), "stderr: {stderr}");
}

#[test]
fn test_cli_build_produces_wasm_file() {
    let path = write_temp("build_test.rune", "policy access { rule allow() { permit } }");
    let output = rune_bin().args(["build", path.to_str().unwrap()]).output().unwrap();
    assert!(output.status.success(), "exit code: {}", output.status);

    let wasm_path = path.with_extension("rune.wasm");
    assert!(wasm_path.exists(), "expected {}", wasm_path.display());
    let bytes = fs::read(&wasm_path).unwrap();
    assert!(bytes.len() > 0);
    // Clean up.
    let _ = fs::remove_file(&wasm_path);
}

#[test]
fn test_cli_version_prints_version() {
    let output = rune_bin().arg("--version").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rune"), "stdout: {stdout}");
    assert!(stdout.contains("0.1.0"), "stdout: {stdout}");
}

#[test]
fn test_cli_unknown_subcommand_exits_nonzero() {
    let output = rune_bin().arg("frobnicate").output().unwrap();
    assert!(!output.status.success());
}

#[test]
fn test_cli_run_valid_policy() {
    let path = write_temp("run_test.rune", "policy access { rule allow() { permit } }");
    let output = rune_bin().args(["run", path.to_str().unwrap()]).output().unwrap();
    assert!(output.status.success(), "exit code: {}", output.status);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Permit"), "stdout: {stdout}");
}

#[test]
fn test_cli_fmt_check_formatted_exits_0() {
    // Already-formatted source.
    let formatted = "policy access {\n    rule allow() {\n        permit\n    }\n}\n";
    let path = write_temp("fmt_ok.rune", formatted);
    let output = rune_bin().args(["fmt", "--check", path.to_str().unwrap()]).output().unwrap();
    assert!(output.status.success(), "exit: {}, stderr: {}", output.status, String::from_utf8_lossy(&output.stderr));
}

#[test]
fn test_cli_fmt_check_unformatted_exits_1() {
    let path = write_temp("fmt_bad.rune", "policy   access{rule   allow()   {permit}}");
    let output = rune_bin().args(["fmt", "--check", path.to_str().unwrap()]).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("would reformat"), "stderr: {stderr}");
}

// ── rune new ────────────────────────────────────────────────────────

#[test]
fn test_cli_new_creates_project() {
    let dir = temp_project_dir("new_creates");
    let parent = dir.parent().unwrap();
    let name = dir.file_name().unwrap().to_str().unwrap();

    let output = rune_bin()
        .args(["new", name])
        .current_dir(parent)
        .output()
        .unwrap();
    assert!(output.status.success(), "exit: {}, stderr: {}", output.status, String::from_utf8_lossy(&output.stderr));

    assert!(dir.join("rune.toml").exists(), "rune.toml should exist");
    assert!(dir.join("src/main.rune").exists(), "src/main.rune should exist");
    assert!(dir.join("README.md").exists(), "README.md should exist");

    // rune.toml should contain the project name.
    let toml = fs::read_to_string(dir.join("rune.toml")).unwrap();
    assert!(toml.contains(name), "rune.toml should contain project name");

    // Clean up.
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_cli_new_fails_if_exists() {
    let dir = temp_project_dir("new_exists");
    let parent = dir.parent().unwrap();
    let name = dir.file_name().unwrap().to_str().unwrap();

    // Create the directory first.
    fs::create_dir_all(&dir).unwrap();

    let output = rune_bin()
        .args(["new", name])
        .current_dir(parent)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("already exists"), "stderr: {stderr}");

    // Clean up.
    let _ = fs::remove_dir_all(&dir);
}

// ── Multi-file projects ─────────────────────────────────────────────

#[test]
fn test_cli_build_multifile_project() {
    let dir = temp_project_dir("multifile_build");
    fs::create_dir_all(&dir).unwrap();

    fs::write(dir.join("main.rune"), r#"
        mod helpers;
        fn add_ten(x: Int) -> Int { helpers::add(x, 10) }
        policy access { rule allow() { permit } }
    "#).unwrap();
    fs::write(dir.join("helpers.rune"), r#"
        pub fn add(a: Int, b: Int) -> Int { a + b }
    "#).unwrap();

    let output = rune_bin()
        .args(["build", dir.join("main.rune").to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "exit: {}, stderr: {}", output.status, String::from_utf8_lossy(&output.stderr));

    let wasm_path = dir.join("main.rune.wasm");
    assert!(wasm_path.exists(), "expected {}", wasm_path.display());
    let bytes = fs::read(&wasm_path).unwrap();
    assert!(!bytes.is_empty());
    // WASM magic bytes.
    assert_eq!(&bytes[0..4], &[0x00, 0x61, 0x73, 0x6D]);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_cli_check_multifile_project() {
    let dir = temp_project_dir("multifile_check");
    fs::create_dir_all(&dir).unwrap();

    fs::write(dir.join("main.rune"), r#"
        mod crypto;
        fn main() -> Bool { crypto::verify() }
    "#).unwrap();
    fs::write(dir.join("crypto.rune"), r#"
        pub fn verify() -> Bool { true }
    "#).unwrap();

    let output = rune_bin()
        .args(["check", dir.join("main.rune").to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "exit: {}, stderr: {}", output.status, String::from_utf8_lossy(&output.stderr));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no errors"), "stderr: {stderr}");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_cli_check_multifile_private_error() {
    let dir = temp_project_dir("multifile_priv");
    fs::create_dir_all(&dir).unwrap();

    fs::write(dir.join("main.rune"), r#"
        mod crypto;
        fn main() -> Bool { crypto::internal() }
    "#).unwrap();
    fs::write(dir.join("crypto.rune"), r#"
        fn internal() -> Bool { false }
    "#).unwrap();

    let output = rune_bin()
        .args(["check", dir.join("main.rune").to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("private"), "stderr: {stderr}");

    let _ = fs::remove_dir_all(&dir);
}

// ── rune doc ────────────────────────────────────────────────────────

#[test]
fn test_cli_doc_generates_markdown() {
    let source = "// An access policy.\npolicy access {\n    rule allow() { permit }\n}\n";
    let path = write_temp("doc_test.rune", source);

    let output = rune_bin()
        .args(["doc", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "exit: {}, stderr: {}", output.status, String::from_utf8_lossy(&output.stderr));

    let md_path = path.with_extension("md");
    assert!(md_path.exists(), "expected {}", md_path.display());
    let md = fs::read_to_string(&md_path).unwrap();
    assert!(md.contains("access"), "markdown should contain 'access'");
    assert!(md.contains("An access policy."), "markdown should contain doc comment");

    // Clean up.
    let _ = fs::remove_file(&md_path);
}
