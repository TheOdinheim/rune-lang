pub mod wasm_gen;

#[cfg(feature = "llvm")]
pub mod llvm_gen;

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "llvm"))]
mod llvm_tests;
