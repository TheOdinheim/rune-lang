// ═══════════════════════════════════════════════════════════════════════
// RUNE VS Code Extension — Language Client
//
// Spawns the rune-lsp binary as a language server and connects via
// stdin/stdout. Provides diagnostics, hover, go-to-definition, and
// completions for .rune files.
// ═══════════════════════════════════════════════════════════════════════

const { LanguageClient, TransportKind } = require("vscode-languageclient/node");
const path = require("path");

let client;

function activate(context) {
    // Find the rune-lsp binary. Check common locations:
    // 1. In PATH (installed via cargo install)
    // 2. In the workspace's target/debug or target/release
    const serverCommand = "rune-lsp";

    const serverOptions = {
        command: serverCommand,
        transport: TransportKind.stdio,
    };

    const clientOptions = {
        documentSelector: [{ scheme: "file", language: "rune" }],
    };

    client = new LanguageClient(
        "rune-lsp",
        "RUNE Language Server",
        serverOptions,
        clientOptions
    );

    client.start();
}

function deactivate() {
    if (client) {
        return client.stop();
    }
}

module.exports = { activate, deactivate };
