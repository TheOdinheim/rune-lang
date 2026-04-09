// ═══════════════════════════════════════════════════════════════════════
// LLVM Backend Benchmarks
//
// Performance benchmarks validating RUNE meets the P25/ASTRO 25 latency
// requirements: policy enforcement adding >10ms is operationally impactful.
// Target: <1ms per policy decision (AWS Cedar benchmark: ~7µs).
//
// Uses generous upper bounds to avoid flaky tests on slow CI machines.
// Printed timings give developers visibility into actual performance.
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use crate::compiler::compile_source;
    use crate::runtime::evaluator::{PolicyModule, PolicyRequest};

    const RISK_POLICY: &str = r#"
        policy risk_based {
            rule check(subject: Int, action: Int, resource: Int, risk: Int) {
                if risk > 50 { deny } else { permit }
            }
        }
    "#;

    // ── WASM evaluation benchmark ───────────────────────────────────

    #[test]
    fn bench_wasm_evaluation() {
        let wasm_bytes = compile_source(RISK_POLICY, 0).unwrap();
        let module = PolicyModule::from_bytes(&wasm_bytes).unwrap();
        let evaluator = module.evaluator().unwrap();

        let iterations = 1000;
        let request = PolicyRequest::new(0, 0, 0, 30);

        let start = Instant::now();
        for _ in 0..iterations {
            let _ = evaluator.evaluate(&request).unwrap();
        }
        let elapsed = start.elapsed();
        let avg_us = elapsed.as_micros() as f64 / iterations as f64;

        eprintln!(
            "WASM evaluation: {:.1} µs avg ({} iterations in {:.1} ms)",
            avg_us,
            iterations,
            elapsed.as_secs_f64() * 1000.0
        );
    }

    #[test]
    fn test_wasm_evaluation_under_1ms() {
        let wasm_bytes = compile_source(RISK_POLICY, 0).unwrap();
        let module = PolicyModule::from_bytes(&wasm_bytes).unwrap();
        let evaluator = module.evaluator().unwrap();

        let iterations = 100;
        let request = PolicyRequest::new(0, 0, 0, 30);

        let start = Instant::now();
        for _ in 0..iterations {
            let _ = evaluator.evaluate(&request).unwrap();
        }
        let elapsed = start.elapsed();
        let avg_ms = elapsed.as_secs_f64() * 1000.0 / iterations as f64;

        assert!(
            avg_ms < 1.0,
            "WASM evaluation should average under 1ms, got {:.3} ms",
            avg_ms
        );
    }

    // ── Native compilation benchmark ────────────────────────────────

    #[test]
    fn bench_native_compilation() {
        use crate::compiler::compile_to_native;

        let start = Instant::now();
        let result = compile_to_native(RISK_POLICY, 0);
        let elapsed = start.elapsed();

        assert!(result.is_ok(), "{:?}", result.err());
        eprintln!(
            "Native compilation: {:.1} ms ({} bytes)",
            elapsed.as_secs_f64() * 1000.0,
            result.unwrap().len()
        );
    }

    #[test]
    fn test_native_compilation_under_30s() {
        use crate::compiler::compile_to_native;

        let start = Instant::now();
        let result = compile_to_native(RISK_POLICY, 0);
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        assert!(
            elapsed.as_secs() < 30,
            "LLVM compilation should complete in under 30s, took {:.1}s",
            elapsed.as_secs_f64()
        );
    }

    // ── Native executable benchmark ─────────────────────────────────

    #[test]
    fn bench_native_executable_run() {
        use crate::compiler::compile_to_executable;

        let dir = std::env::temp_dir().join("rune_bench_exe");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("bench_policy.bin");
        let _ = std::fs::remove_file(&output);

        let result = compile_to_executable(RISK_POLICY, 0, &output);
        if let Err(ref errors) = result {
            if errors.iter().any(|e| e.message.contains("'cc'")) {
                eprintln!("skipping native exe benchmark: linker not available");
                return;
            }
        }
        assert!(result.is_ok(), "{:?}", result.err());

        let iterations = 100;
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = std::process::Command::new(&output).output().unwrap();
        }
        let elapsed = start.elapsed();
        let avg_ms = elapsed.as_secs_f64() * 1000.0 / iterations as f64;

        eprintln!(
            "Native exe run: {:.1} ms avg ({} iterations in {:.1} ms)",
            avg_ms,
            iterations,
            elapsed.as_secs_f64() * 1000.0
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_native_executable_under_10ms() {
        use crate::compiler::compile_to_executable;

        let dir = std::env::temp_dir().join("rune_bench_exe_10ms");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("fast_policy.bin");
        let _ = std::fs::remove_file(&output);

        let result = compile_to_executable(RISK_POLICY, 0, &output);
        if let Err(ref errors) = result {
            if errors.iter().any(|e| e.message.contains("'cc'")) {
                eprintln!("skipping: linker not available");
                return;
            }
        }
        assert!(result.is_ok(), "{:?}", result.err());

        // Warm up (first run loads dynamic linker, caches, etc.)
        let _ = std::process::Command::new(&output).output().unwrap();

        let iterations = 50;
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = std::process::Command::new(&output).output().unwrap();
        }
        let elapsed = start.elapsed();
        let avg_ms = elapsed.as_secs_f64() * 1000.0 / iterations as f64;

        assert!(
            avg_ms < 10.0,
            "Native exe should run under 10ms avg, got {:.3} ms",
            avg_ms
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Shared library size benchmark ───────────────────────────────

    #[test]
    fn bench_shared_library_size() {
        use crate::compiler::compile_to_shared_library;

        let dir = std::env::temp_dir().join("rune_bench_so_size");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("bench.so");
        let _ = std::fs::remove_file(&output);

        let result = compile_to_shared_library(RISK_POLICY, 0, &output);
        if let Err(ref errors) = result {
            if errors.iter().any(|e| e.message.contains("'cc'")) {
                eprintln!("skipping: linker not available");
                return;
            }
        }
        assert!(result.is_ok(), "{:?}", result.err());

        let size = std::fs::metadata(&output).unwrap().len();
        eprintln!("Shared library size: {} bytes ({:.1} KB)", size, size as f64 / 1024.0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Comparison: native vs WASM cold start ───────────────────────

    #[test]
    fn test_timing_comparison() {
        use crate::compiler::compile_to_executable;

        // WASM cold start: module load + first evaluation
        let wasm_bytes = compile_source(RISK_POLICY, 0).unwrap();
        let wasm_start = Instant::now();
        let module = PolicyModule::from_bytes(&wasm_bytes).unwrap();
        let evaluator = module.evaluator().unwrap();
        let request = PolicyRequest::new(0, 0, 0, 30);
        let _ = evaluator.evaluate(&request).unwrap();
        let wasm_cold = wasm_start.elapsed();

        // WASM warm evaluation (avg of 100)
        let wasm_warm_start = Instant::now();
        for _ in 0..100 {
            let _ = evaluator.evaluate(&request).unwrap();
        }
        let wasm_warm_avg =
            wasm_warm_start.elapsed().as_secs_f64() * 1000.0 / 100.0;

        // Native exe
        let dir = std::env::temp_dir().join("rune_bench_compare");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("compare.bin");
        let _ = std::fs::remove_file(&output);

        let result = compile_to_executable(RISK_POLICY, 0, &output);
        if let Err(ref errors) = result {
            if errors.iter().any(|e| e.message.contains("'cc'")) {
                eprintln!("skipping timing comparison: linker not available");
                eprintln!("WASM cold start:   {:.3} ms", wasm_cold.as_secs_f64() * 1000.0);
                eprintln!("WASM warm eval:    {:.3} ms avg", wasm_warm_avg);
                return;
            }
        }
        assert!(result.is_ok(), "{:?}", result.err());

        // Warm up
        let _ = std::process::Command::new(&output).output().unwrap();

        let native_start = Instant::now();
        for _ in 0..50 {
            let _ = std::process::Command::new(&output).output().unwrap();
        }
        let native_avg =
            native_start.elapsed().as_secs_f64() * 1000.0 / 50.0;

        eprintln!("=== Timing Comparison ===");
        eprintln!(
            "WASM cold start:   {:.3} ms",
            wasm_cold.as_secs_f64() * 1000.0
        );
        eprintln!("WASM warm eval:    {:.3} ms avg", wasm_warm_avg);
        eprintln!("Native exe run:    {:.3} ms avg (includes process spawn)", native_avg);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
