# rune-python

Python integration for the RUNE governance-first policy engine.

## Installation

```bash
pip install rune-python
```

## Quick Start

```python
import rune

engine = rune.load("policy.rune.wasm")
decision = engine.evaluate(subject_id=1, action=2, risk_score=85)

if decision.denied:
    print(f"Access denied: {decision.outcome}")
```

## API Reference

### `rune.load(wasm_path) -> PolicyEngine`

Load a RUNE policy module from a compiled `.rune.wasm` file.

### `PolicyEngine`

```python
# From a compiled WASM file
engine = PolicyEngine(wasm_path="policy.rune.wasm")

# From raw WASM bytes
engine = PolicyEngine(wasm_bytes=wasm_data)

# From RUNE source (requires rune-lang CLI on PATH)
engine = PolicyEngine(source="policy AccessControl { ... }")
```

**Methods:**

- `evaluate(subject_id=0, action=0, resource_id=0, risk_score=0) -> Decision`
  Evaluate a policy request. Always returns a Decision (fail-closed).

- `evaluate_dict(request: dict) -> Decision`
  Evaluate from a dictionary with keys: subject_id, action, resource_id, risk_score.

- `audit_count -> int`
  Number of evaluations performed.

### `Decision`

```python
decision.outcome          # "Permit", "Deny", "Escalate", "Quarantine"
decision.permitted        # True if outcome is "Permit"
decision.denied           # True if outcome is "Deny"
decision.matched_rule     # Name of the matching rule
decision.evaluation_time_ms  # Evaluation time in milliseconds
decision.error            # Error message, or None
```

### `RuneError`

Exception raised on RUNE engine errors (invalid WASM, missing CLI, etc.).

## Compiling RUNE Source

To compile `.rune` files to `.wasm`, install the RUNE compiler:

```bash
cargo install rune-lang
rune-lang build policy.rune
# produces policy.rune.wasm
```
