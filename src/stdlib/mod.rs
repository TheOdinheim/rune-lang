// ═══════════════════════════════════════════════════════════════════════
// RUNE Standard Library
//
// Provides runtime-accessible modules for RUNE programs via FFI.
// Each module corresponds to a rune:: namespace that RUNE source code
// can call through extern declarations.
//
// PQC-first: cryptographic primitives default to post-quantum algorithms
// (SHA-3 for hashing, ML-DSA for signatures). Classical algorithms are
// explicit fallbacks, not defaults.
// ═══════════════════════════════════════════════════════════════════════

pub mod crypto;
