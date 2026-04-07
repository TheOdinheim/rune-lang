use std::fs;
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};

use rune_lang::compiler::{check_source, compile_source, CompileError};
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
        /// Path to the .rune source file
        file: PathBuf,
    },
    /// Type-check a .rune file without generating WASM
    Check {
        /// Path to the .rune source file
        file: PathBuf,
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
}

// ── Main ─────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Build { file } => cmd_build(&file),
        Commands::Check { file } => cmd_check(&file),
        Commands::Run { file, subject, action, resource, risk } => {
            cmd_run(&file, subject, action, resource, risk)
        }
    }
}

// ── Subcommands ──────────────────────────────────────────────────────

fn cmd_build(path: &PathBuf) {
    let source = read_source(path);

    match compile_source(&source, 0) {
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

    match check_source(&source, 0) {
        Ok(()) => {
            eprintln!("{}ok:{} {} — no errors", GREEN, RESET, path.display());
        }
        Err(errors) => {
            report_errors(path, &source, &errors);
            process::exit(EXIT_COMPILE_ERROR);
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
