"""Tests for the rune-python package.

Tests that require wasmtime are skipped if wasmtime is not installed.
The structural tests (Decision, RuneError) run without external dependencies.
"""

import sys
import pytest

# Import the package — this always works (no wasmtime needed at import time).
from rune import Decision, PolicyEngine, RuneError, load


# ── Decision tests ────────────────────────────────────────────────────

class TestDecision:
    def test_construction(self):
        d = Decision("Permit")
        assert d.outcome == "Permit"
        assert d.matched_rule == ""
        assert d.evaluation_time_ms == 0.0
        assert d.error is None

    def test_permitted(self):
        assert Decision("Permit").permitted is True
        assert Decision("Deny").permitted is False

    def test_denied(self):
        assert Decision("Deny").denied is True
        assert Decision("Permit").denied is False

    def test_repr(self):
        assert repr(Decision("Permit")) == "Decision(Permit)"
        assert repr(Decision("Deny")) == "Decision(Deny)"
        assert repr(Decision("Escalate")) == "Decision(Escalate)"
        assert repr(Decision("Quarantine")) == "Decision(Quarantine)"

    def test_equality(self):
        assert Decision("Permit") == Decision("Permit")
        assert Decision("Permit") != Decision("Deny")

    def test_from_i32(self):
        assert Decision._from_i32(0).outcome == "Permit"
        assert Decision._from_i32(1).outcome == "Deny"
        assert Decision._from_i32(2).outcome == "Escalate"
        assert Decision._from_i32(3).outcome == "Quarantine"
        assert Decision._from_i32(99).outcome == "Deny"  # unknown → Deny

    def test_error_field(self):
        d = Decision("Deny", error="something broke")
        assert d.denied
        assert d.error == "something broke"


# ── RuneError tests ───────────────────────────────────────────────────

class TestRuneError:
    def test_raise_and_catch(self):
        with pytest.raises(RuneError, match="test error"):
            raise RuneError("test error")

    def test_is_exception(self):
        assert issubclass(RuneError, Exception)


# ── PolicyEngine constructor validation ───────────────────────────────

class TestPolicyEngineValidation:
    def test_no_args_raises(self):
        with pytest.raises(RuneError, match="one of"):
            PolicyEngine()

    def test_load_function_signature(self):
        """load() accepts a wasm_path string."""
        # We can't actually load a WASM file without one, but verify
        # that the function exists and has the right signature.
        assert callable(load)


# ── Integration tests (require wasmtime) ──────────────────────────────

try:
    import wasmtime
    HAS_WASMTIME = True
except ImportError:
    HAS_WASMTIME = False


@pytest.mark.skipif(not HAS_WASMTIME, reason="wasmtime not available")
class TestPolicyEngineWithWasmtime:
    def test_invalid_wasm_bytes(self):
        with pytest.raises(RuneError, match="failed to load"):
            PolicyEngine(wasm_bytes=b"not valid wasm")

    def test_invalid_wasm_path(self):
        with pytest.raises((RuneError, FileNotFoundError)):
            PolicyEngine(wasm_path="/nonexistent/policy.wasm")
