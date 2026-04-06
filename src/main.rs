use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use rune_lang::compiler::compile_source;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: rune build <file.rune>");
        process::exit(1);
    }

    match args[1].as_str() {
        "build" => {
            if args.len() < 3 {
                eprintln!("Usage: rune build <file.rune>");
                process::exit(1);
            }
            build(&args[2]);
        }
        other => {
            eprintln!("Unknown command: {other}");
            eprintln!("Usage: rune build <file.rune>");
            process::exit(1);
        }
    }
}

fn build(path: &str) {
    let source_path = PathBuf::from(path);

    let source = match fs::read_to_string(&source_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error reading {}: {e}", source_path.display());
            process::exit(1);
        }
    };

    match compile_source(&source, 0) {
        Ok(wasm_bytes) => {
            let output_path = source_path.with_extension("rune.wasm");
            if let Err(e) = fs::write(&output_path, &wasm_bytes) {
                eprintln!("Error writing {}: {e}", output_path.display());
                process::exit(1);
            }
            println!(
                "Compiled {} → {} ({} bytes)",
                source_path.display(),
                output_path.display(),
                wasm_bytes.len()
            );
        }
        Err(errors) => {
            for e in &errors {
                eprintln!("{e}");
            }
            eprintln!(
                "\n{} error{} found",
                errors.len(),
                if errors.len() == 1 { "" } else { "s" }
            );
            process::exit(1);
        }
    }
}
