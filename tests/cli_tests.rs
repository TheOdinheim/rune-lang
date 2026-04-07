use std::fs;
use std::process::Command;

fn rune_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rune-lang"))
}

fn write_temp(name: &str, content: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("rune_cli_tests");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    fs::write(&path, content).unwrap();
    path
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
