// ═══════════════════════════════════════════════════════════════════════
// RUNE Playground — JavaScript Glue
//
// Loads the RUNE WASM module (compiled from Rust via wasm-pack) and
// wires the editor buttons to the compiler functions.
// ═══════════════════════════════════════════════════════════════════════

let runeModule = null;
let editor = null;

const STARTER_SOURCE = `// A simple access control policy.
// Click "Check" to type-check, "Build" to compile to WASM.
policy access_control {
    rule evaluate(risk_score: Int) {
        if risk_score > 80 { deny } else { permit }
    }
}
`;

// ── Initialize ──────────────────────────────────────────────────────

async function init() {
    // Set up CodeMirror editor.
    setupEditor();

    // Load the RUNE WASM module.
    try {
        const mod = await import("./pkg/rune_lang.js");
        await mod.default();
        runeModule = mod;
        appendOutput("RUNE compiler loaded. Ready.", "output-success");
    } catch (e) {
        appendOutput(
            "Could not load RUNE compiler WASM module.\n" +
            "Run tools/playground/build.sh first.\n\n" +
            "Error: " + e.message,
            "output-warning"
        );
    }
}

function setupEditor() {
    const parent = document.getElementById("editor");
    if (!parent) return;

    // Check if CodeMirror is available.
    if (typeof EditorView !== "undefined") {
        const runeHighlight = StreamLanguage.define({
            token(stream) {
                if (stream.match(/\/\/.*/)) return "comment";
                if (stream.match(/"(?:[^"\\]|\\.)*"/)) return "string";
                if (stream.match(/\b(?:policy|rule|fn|let|if|else|match|while|for|return|permit|deny|escalate|quarantine|struct|enum|type|trait|impl|mod|use|const|capability|effect|attest|audit|secure_zone|unsafe_ffi|require|where|true|false)\b/))
                    return "keyword";
                if (stream.match(/\b(?:Int|Float|Bool|String|Unit|List|Map|Option|Result)\b/))
                    return "typeName";
                if (stream.match(/\b\d+(?:\.\d+)?(?:e[+-]?\d+)?\b/)) return "number";
                if (stream.match(/[{}()\[\];,.:]/)) return "punctuation";
                if (stream.match(/[+\-*/%=<>!&|^~?]+/)) return "operator";
                if (stream.match(/[a-zA-Z_]\w*/)) return "variableName";
                stream.next();
                return null;
            },
            startState() { return {}; }
        });

        editor = new EditorView({
            doc: STARTER_SOURCE,
            extensions: [
                basicSetup,
                runeHighlight,
                EditorView.theme({
                    "&": { height: "100%" },
                    ".cm-scroller": { overflow: "auto" },
                }),
            ],
            parent,
        });
    } else {
        // Fallback: plain textarea.
        const textarea = document.createElement("textarea");
        textarea.id = "editor-textarea";
        textarea.value = STARTER_SOURCE;
        textarea.style.cssText =
            "width:100%;height:100%;background:var(--bg-editor);color:var(--text);" +
            "font-family:var(--font-mono);font-size:0.9rem;line-height:1.5;" +
            "border:none;padding:0.75rem;resize:none;outline:none;";
        parent.appendChild(textarea);
    }
}

function getSource() {
    if (editor) return editor.state.doc.toString();
    const textarea = document.getElementById("editor-textarea");
    return textarea ? textarea.value : "";
}

function setSource(text) {
    if (editor) {
        editor.dispatch({
            changes: { from: 0, to: editor.state.doc.length, insert: text },
        });
    } else {
        const textarea = document.getElementById("editor-textarea");
        if (textarea) textarea.value = text;
    }
}

// ── Output ──────────────────────────────────────────────────────────

function clearOutput() {
    const el = document.getElementById("output");
    if (el) el.innerHTML = "";
}

function appendOutput(text, className) {
    const el = document.getElementById("output");
    if (!el) return;
    const span = document.createElement("span");
    span.className = className || "";
    span.textContent = text + "\n";
    el.appendChild(span);
    el.scrollTop = el.scrollHeight;
}

// ── Actions ─────────────────────────────────────────────────────────

function actionCheck() {
    if (!runeModule) {
        appendOutput("Compiler not loaded.", "output-error");
        return;
    }
    clearOutput();
    const source = getSource();
    const start = performance.now();
    const resultJson = runeModule.check(source);
    const elapsed = (performance.now() - start).toFixed(2);

    try {
        const result = JSON.parse(resultJson);
        if (result.success) {
            appendOutput(`Check passed (${elapsed}ms) -- no errors.`, "output-success");
        } else {
            appendOutput(`Check failed (${elapsed}ms):`, "output-error");
            for (const err of result.errors) {
                appendOutput("  " + err, "output-error");
            }
        }
    } catch {
        appendOutput("Unexpected response: " + resultJson, "output-warning");
    }
}

function actionBuild() {
    if (!runeModule) {
        appendOutput("Compiler not loaded.", "output-error");
        return;
    }
    clearOutput();
    const source = getSource();

    // First check for errors.
    const checkJson = runeModule.check(source);
    const checkResult = JSON.parse(checkJson);
    if (!checkResult.success) {
        appendOutput("Compilation failed:", "output-error");
        for (const err of checkResult.errors) {
            appendOutput("  " + err, "output-error");
        }
        return;
    }

    const start = performance.now();
    const wasmBytes = runeModule.compile(source);
    const elapsed = (performance.now() - start).toFixed(2);

    if (wasmBytes.length === 0) {
        appendOutput("Compilation produced no output.", "output-error");
        return;
    }

    appendOutput(
        `Compiled successfully (${elapsed}ms) -- ${wasmBytes.length} bytes of WASM.`,
        "output-success"
    );
    appendOutput(
        `WASM magic: ${Array.from(wasmBytes.slice(0, 4)).map(b => "0x" + b.toString(16).padStart(2, "0")).join(" ")}`,
        "output-info"
    );

    // Try to instantiate and run in the browser.
    runWasm(wasmBytes);
}

async function runWasm(wasmBytes) {
    try {
        const { instance } = await WebAssembly.instantiate(wasmBytes);
        const exports = Object.keys(instance.exports);
        appendOutput(`Exports: ${exports.join(", ")}`, "output-info");

        if (instance.exports.evaluate) {
            const result = instance.exports.evaluate(0n, 0n, 0n, 0n);
            const decisions = ["Permit", "Deny", "Escalate", "Quarantine"];
            const decision = decisions[Number(result)] || `Unknown(${result})`;
            appendOutput(`\nevaluate(0, 0, 0, 0) = ${decision}`, "output-success");
        }
    } catch (e) {
        appendOutput("WASM instantiation: " + e.message, "output-warning");
    }
}

function actionFormat() {
    if (!runeModule) {
        appendOutput("Compiler not loaded.", "output-error");
        return;
    }
    clearOutput();
    const source = getSource();
    const resultJson = runeModule.format(source);

    try {
        const result = JSON.parse(resultJson);
        if (result.success) {
            setSource(result.formatted);
            appendOutput("Formatted.", "output-success");
        } else {
            appendOutput("Format failed:", "output-error");
            for (const err of result.errors) {
                appendOutput("  " + err, "output-error");
            }
        }
    } catch {
        appendOutput("Unexpected response: " + resultJson, "output-warning");
    }
}

// ── Boot ────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", init);
