use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use clap::{Parser, Subcommand};

use rune_lang::compiler::{check_project, compile_project, CompileError};
use rune_lang::docgen::{extract_docs, render_markdown};
use rune_lang::formatter::format_source;
use rune_lang::manifest::RuneManifest;
use rune_lang::runtime::evaluator::{PolicyDecision, PolicyRequest};
use rune_lang::runtime::pipeline::compile_and_load;

// ── Exit codes ───────────────────────────────────────────────────────

const EXIT_SUCCESS: i32 = 0;
const EXIT_COMPILE_ERROR: i32 = 1;
const EXIT_RUNTIME_ERROR: i32 = 2;
const EXIT_USAGE_ERROR: i32 = 3;

// ── CLI definition ───────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "rune",
    version,
    about = "The RUNE governance-first programming language compiler",
    long_about = "RUNE compiles governance policies into verifiable WASM modules.\n\
                  Every policy decision is cryptographically audited.\n\
                  Four pillars: Security Baked In, Assumed Breach, Zero Trust, No Single Points of Failure."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compile a .rune file to WASM bytecode
    Build {
        /// Path to the .rune source file (defaults to src/main.rune if rune.toml exists)
        file: Option<PathBuf>,
    },
    /// Type-check a .rune file without generating WASM
    Check {
        /// Path to the .rune source file (defaults to src/main.rune if rune.toml exists)
        file: Option<PathBuf>,
    },
    /// Format a .rune file with canonical style
    Fmt {
        /// Path to the .rune source file
        file: PathBuf,
        /// Check if the file is already formatted (exit 1 if not)
        #[arg(long)]
        check: bool,
    },
    /// Compile and run a .rune file with a default policy evaluation
    Run {
        /// Path to the .rune source file
        file: PathBuf,
        /// Subject ID for the evaluation (default: 0)
        #[arg(long, default_value_t = 0)]
        subject: i64,
        /// Action ID for the evaluation (default: 0)
        #[arg(long, default_value_t = 0)]
        action: i64,
        /// Resource ID for the evaluation (default: 0)
        #[arg(long, default_value_t = 0)]
        resource: i64,
        /// Risk score for the evaluation (default: 0)
        #[arg(long, default_value_t = 0)]
        risk: i64,
    },
    /// Create a new RUNE project
    New {
        /// Project name (lowercase alphanumeric + hyphens)
        name: String,
    },
    /// Generate documentation from a .rune source file
    Doc {
        /// Path to the .rune source file
        file: PathBuf,
        /// Print to stdout instead of writing a file
        #[arg(long)]
        stdout: bool,
    },
}

// ── Main ─────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Build { file } => {
            let file = resolve_source_file(file);
            cmd_build(&file);
        }
        Commands::Check { file } => {
            let file = resolve_source_file(file);
            cmd_check(&file);
        }
        Commands::Fmt { file, check } => cmd_fmt(&file, check),
        Commands::Run { file, subject, action, resource, risk } => {
            cmd_run(&file, subject, action, resource, risk)
        }
        Commands::New { name } => cmd_new(&name),
        Commands::Doc { file, stdout } => cmd_doc(&file, stdout),
    }
}

// ── Subcommands ──────────────────────────────────────────────────────

fn cmd_build(path: &PathBuf) {
    let source = read_source(path);

    match compile_project(path) {
        Ok(wasm_bytes) => {
            let output_path = path.with_extension("rune.wasm");
            if let Err(e) = fs::write(&output_path, &wasm_bytes) {
                eprintln!("{}error:{} failed to write {}: {e}", RED, RESET, output_path.display());
                process::exit(EXIT_COMPILE_ERROR);
            }
            eprintln!(
                "{}ok:{} {} -> {} ({} bytes)",
                GREEN, RESET,
                path.display(),
                output_path.display(),
                wasm_bytes.len()
            );
        }
        Err(errors) => {
            report_errors(path, &source, &errors);
            process::exit(EXIT_COMPILE_ERROR);
        }
    }
}

fn cmd_check(path: &PathBuf) {
    let source = read_source(path);

    match check_project(path) {
        Ok(()) => {
            eprintln!("{}ok:{} {} — no errors", GREEN, RESET, path.display());
        }
        Err(errors) => {
            report_errors(path, &source, &errors);
            process::exit(EXIT_COMPILE_ERROR);
        }
    }
}

fn cmd_fmt(path: &PathBuf, check: bool) {
    let source = read_source(path);

    let formatted = match format_source(&source) {
        Ok(f) => f,
        Err(errors) => {
            report_errors(path, &source, &errors);
            process::exit(EXIT_COMPILE_ERROR);
        }
    };

    if check {
        if source == formatted {
            eprintln!("{}ok:{} {} already formatted", GREEN, RESET, path.display());
        } else {
            eprintln!(
                "{}would reformat:{} {}",
                YELLOW, RESET, path.display()
            );
            process::exit(EXIT_COMPILE_ERROR);
        }
    } else {
        if source == formatted {
            eprintln!("{}already formatted:{} {}", GREEN, RESET, path.display());
        } else {
            if let Err(e) = fs::write(path, &formatted) {
                eprintln!("{}error:{} failed to write {}: {e}", RED, RESET, path.display());
                process::exit(EXIT_COMPILE_ERROR);
            }
            eprintln!("{}formatted:{} {}", GREEN, RESET, path.display());
        }
    }
}

fn cmd_run(path: &PathBuf, subject: i64, action: i64, resource: i64, risk: i64) {
    let source = read_source(path);

    let module = match compile_and_load(&source) {
        Ok(m) => m,
        Err(rune_lang::runtime::evaluator::RuntimeError::CompilationFailed(msg)) => {
            eprintln!("{}error:{} compilation failed: {msg}", RED, RESET);
            process::exit(EXIT_COMPILE_ERROR);
        }
        Err(e) => {
            eprintln!("{}error:{} {e}", RED, RESET);
            process::exit(EXIT_RUNTIME_ERROR);
        }
    };

    if !module.has_evaluate() {
        eprintln!(
            "{}warning:{} no policies found — module has no evaluate entry point",
            YELLOW, RESET
        );
        process::exit(EXIT_SUCCESS);
    }

    let evaluator = match module.evaluator() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{}error:{} {e}", RED, RESET);
            process::exit(EXIT_RUNTIME_ERROR);
        }
    };

    let request = PolicyRequest::new(subject, action, resource, risk);

    match evaluator.evaluate(&request) {
        Ok(result) => {
            let decision_color = match result.decision {
                PolicyDecision::Permit => GREEN,
                PolicyDecision::Deny => RED,
                PolicyDecision::Escalate => YELLOW,
                PolicyDecision::Quarantine => RED,
            };
            println!(
                "{}{}{} ({:.3}ms)",
                decision_color,
                result.decision,
                RESET,
                result.evaluation_duration.as_secs_f64() * 1000.0
            );
        }
        Err(e) => {
            eprintln!("{}error:{} evaluation failed: {e}", RED, RESET);
            process::exit(EXIT_RUNTIME_ERROR);
        }
    }
}

fn cmd_new(name: &str) {
    let project_dir = PathBuf::from(name);

    if project_dir.exists() {
        eprintln!("{}error:{} directory '{}' already exists", RED, RESET, name);
        process::exit(EXIT_COMPILE_ERROR);
    }

    let src_dir = project_dir.join("src");
    if let Err(e) = fs::create_dir_all(&src_dir) {
        eprintln!("{}error:{} failed to create directory: {e}", RED, RESET);
        process::exit(EXIT_COMPILE_ERROR);
    }

    let manifest = RuneManifest::default_new(name);
    let toml_content = manifest.to_toml_string();
    if let Err(e) = fs::write(project_dir.join("rune.toml"), &toml_content) {
        eprintln!("{}error:{} failed to write rune.toml: {e}", RED, RESET);
        process::exit(EXIT_COMPILE_ERROR);
    }

    let main_rune = r#"// A simple access control policy.
// Compile: rune build src/main.rune
// Check:   rune check src/main.rune
// Run:     rune run src/main.rune --risk 50
policy access_control {
    rule evaluate(risk_score: Int) {
        if risk_score > 80 { deny } else { permit }
    }
}
"#;
    if let Err(e) = fs::write(src_dir.join("main.rune"), main_rune) {
        eprintln!("{}error:{} failed to write src/main.rune: {e}", RED, RESET);
        process::exit(EXIT_COMPILE_ERROR);
    }

    let readme = format!(
        "# {name}\n\nA RUNE governance policy project.\n\n## Getting Started\n\n```sh\nrune check src/main.rune\nrune build src/main.rune\nrune run src/main.rune --risk 50\n```\n"
    );
    if let Err(e) = fs::write(project_dir.join("README.md"), &readme) {
        eprintln!("{}error:{} failed to write README.md: {e}", RED, RESET);
        process::exit(EXIT_COMPILE_ERROR);
    }

    eprintln!("{}created:{} {}/", GREEN, RESET, name);
    eprintln!("  rune.toml");
    eprintln!("  src/main.rune");
    eprintln!("  README.md");
}

fn cmd_doc(path: &PathBuf, to_stdout: bool) {
    let source = read_source(path);
    let items = extract_docs(&source);

    let module_name = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "module".to_string());

    let markdown = render_markdown(&items, &module_name);

    if to_stdout {
        print!("{markdown}");
    } else {
        let output_path = path.with_extension("md");
        if let Err(e) = fs::write(&output_path, &markdown) {
            eprintln!("{}error:{} failed to write {}: {e}", RED, RESET, output_path.display());
            process::exit(EXIT_COMPILE_ERROR);
        }
        eprintln!("{}generated:{} {}", GREEN, RESET, output_path.display());
    }
}

// ── Project-aware helpers ───────────────────────────────────────────

fn find_manifest(start: &Path) -> Option<PathBuf> {
    let mut dir = if start.is_file() {
        start.parent()?.to_path_buf()
    } else {
        start.to_path_buf()
    };

    loop {
        let candidate = dir.join("rune.toml");
        if candidate.exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn resolve_source_file(file: Option<PathBuf>) -> PathBuf {
    if let Some(f) = file {
        return f;
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if let Some(manifest_path) = find_manifest(&cwd) {
        let project_dir = manifest_path.parent().unwrap();
        let main_rune = project_dir.join("src").join("main.rune");
        if main_rune.exists() {
            if let Ok(manifest) = RuneManifest::from_file(&manifest_path) {
                eprintln!(
                    "{}info:{} project '{}' — building src/main.rune",
                    GREEN, RESET, manifest.package.name
                );
            }
            return main_rune;
        }
    }

    eprintln!("{}error:{} no file specified and no rune.toml found", RED, RESET);
    process::exit(EXIT_USAGE_ERROR);
}

// ── Error reporting ──────────────────────────────────────────────────

fn report_errors(path: &PathBuf, source: &str, errors: &[CompileError]) {
    let lines: Vec<&str> = source.lines().collect();

    for error in errors {
        let line_num = error.span.line as usize;
        let col_num = error.span.column as usize;

        // Header: file:line:col: phase error: message
        eprintln!(
            "{}error[{}]:{} {}:{}:{}: {}",
            RED, error.phase_tag(), RESET,
            path.display(), line_num, col_num,
            error.message
        );

        // Source line (if available).
        if line_num > 0 && line_num <= lines.len() {
            let line = lines[line_num - 1];
            let line_prefix = format!("{line_num} | ");
            eprintln!("  {}{}", line_prefix, line);

            // Caret pointing to the error.
            let padding = " ".repeat(line_prefix.len() + col_num.saturating_sub(1));
            eprintln!("  {}{}^{}", padding, RED, RESET);
        }

        eprintln!();
    }

    eprintln!(
        "{} error{} found",
        errors.len(),
        if errors.len() == 1 { "" } else { "s" }
    );
}

fn read_source(path: &PathBuf) -> String {
    match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}error:{} cannot read {}: {e}", RED, RESET, path.display());
            process::exit(EXIT_USAGE_ERROR);
        }
    }
}

// ── ANSI color codes ─────────────────────────────────────────────────

const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";
