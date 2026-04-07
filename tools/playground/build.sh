#!/bin/bash
# Build the RUNE playground WASM module.
# Requires: wasm-pack (cargo install wasm-pack)
#           rustup target add wasm32-unknown-unknown
set -e
cd "$(dirname "$0")/../.."
wasm-pack build --target web --no-default-features --features playground --out-dir tools/playground/pkg
echo "Playground built successfully. Open tools/playground/index.html"
