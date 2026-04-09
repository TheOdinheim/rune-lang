"""Example: Using rune-python from a Python application.

This demonstrates the complete workflow for evaluating RUNE governance
policies from Python. Install with:

    pip install rune-python

The policy must be pre-compiled to WASM using the RUNE compiler:

    rune-lang build policy.rune
    # produces policy.rune.wasm
"""

import rune


def main():
    # ── 1. Load a compiled policy ─────────────────────────────────
    engine = rune.load("policy.rune.wasm")

    # ── 2. Evaluate a request ─────────────────────────────────────
    decision = engine.evaluate(
        subject_id=42,
        action=1,
        resource_id=100,
        risk_score=85,
    )

    # ── 3. Check the decision ─────────────────────────────────────
    if decision.denied:
        print(f"Access denied: {decision.outcome}")
    elif decision.permitted:
        print(f"Access granted: {decision.outcome}")
    else:
        print(f"Decision: {decision.outcome}")

    # ── 4. Evaluate from a dictionary (useful for REST handlers) ──
    request = {
        "subject_id": 1,
        "action": 2,
        "resource_id": 3,
        "risk_score": 50,
    }
    decision = engine.evaluate_dict(request)
    print(f"Dict evaluation: {decision}")

    # ── 5. Check audit count ──────────────────────────────────────
    print(f"Evaluations performed: {engine.audit_count}")

    # ── 6. Error handling (fail-closed) ───────────────────────────
    # If anything goes wrong, the decision is always Deny.
    # RuneError is raised only for setup errors (bad WASM, missing file).
    try:
        bad_engine = rune.PolicyEngine(wasm_path="nonexistent.wasm")
    except rune.RuneError as e:
        print(f"Setup error (expected): {e}")


if __name__ == "__main__":
    main()
