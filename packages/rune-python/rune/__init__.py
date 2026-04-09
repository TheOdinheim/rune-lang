"""
rune-python — Python integration for the RUNE governance-first policy engine.

Load and evaluate RUNE governance policy modules from Python. Policies
are compiled to WASM and executed via wasmtime for sandboxed evaluation.

Pillar: Security Baked In — fail-closed by default. Errors produce Deny.
Pillar: Assumed Breach — every evaluation is audit-recorded in the module.

Quick start:
    >>> engine = rune.load("policy.rune.wasm")
    >>> decision = engine.evaluate(subject_id=1, action=2, risk_score=85)
    >>> decision.denied
    True
"""

from __future__ import annotations

import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional


class RuneError(Exception):
    """Error from the RUNE policy engine."""
    pass


class Decision:
    """The result of a policy evaluation.

    Attributes:
        outcome: One of "Permit", "Deny", "Escalate", "Quarantine".
        matched_rule: Name of the rule that produced this decision.
        evaluation_time_ms: Time spent evaluating, in milliseconds.
        error: Error message if evaluation failed (outcome will be "Deny").
    """

    _OUTCOME_MAP = {0: "Permit", 1: "Deny", 2: "Escalate", 3: "Quarantine"}

    def __init__(
        self,
        outcome: str,
        matched_rule: str = "",
        evaluation_time_ms: float = 0.0,
        error: Optional[str] = None,
    ):
        self.outcome = outcome
        self.matched_rule = matched_rule
        self.evaluation_time_ms = evaluation_time_ms
        self.error = error

    @classmethod
    def _from_i32(cls, value: int) -> "Decision":
        outcome = cls._OUTCOME_MAP.get(value, "Deny")
        return cls(outcome=outcome)

    @property
    def permitted(self) -> bool:
        """True if the policy decision is Permit."""
        return self.outcome == "Permit"

    @property
    def denied(self) -> bool:
        """True if the policy decision is Deny."""
        return self.outcome == "Deny"

    def __repr__(self) -> str:
        return f"Decision({self.outcome})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Decision):
            return self.outcome == other.outcome
        return NotImplemented


class PolicyEngine:
    """Load and evaluate RUNE governance policy modules.

    Create from a compiled .wasm file, raw WASM bytes, or RUNE source code
    (source compilation requires the rune-lang CLI to be on PATH).

    Thread safety: each thread should create its own PolicyEngine instance.

    Examples:
        >>> engine = PolicyEngine(wasm_path="policy.rune.wasm")
        >>> decision = engine.evaluate(risk_score=90)
        >>> decision.denied
        True
    """

    def __init__(
        self,
        wasm_path: Optional[str] = None,
        wasm_bytes: Optional[bytes] = None,
        source: Optional[str] = None,
    ):
        if wasm_path is None and wasm_bytes is None and source is None:
            raise RuneError("one of wasm_path, wasm_bytes, or source must be provided")

        try:
            import wasmtime
        except ImportError:
            raise RuneError(
                "wasmtime package is required: pip install wasmtime"
            ) from None

        if source is not None:
            wasm_bytes = self._compile_source(source)

        if wasm_path is not None:
            with open(wasm_path, "rb") as f:
                wasm_bytes = f.read()

        self._engine = wasmtime.Engine()
        try:
            self._module = wasmtime.Module(self._engine, wasm_bytes)
        except Exception as e:
            raise RuneError(f"failed to load WASM module: {e}") from e

        self._store = wasmtime.Store(self._engine)
        try:
            self._instance = wasmtime.Instance(self._store, self._module, [])
        except Exception as e:
            raise RuneError(f"failed to instantiate WASM module: {e}") from e

        self._evaluate_fn = self._instance.exports(self._store).get("evaluate")
        if self._evaluate_fn is None:
            raise RuneError("WASM module does not export an 'evaluate' function")

        self._eval_count = 0

    def evaluate(
        self,
        subject_id: int = 0,
        action: int = 0,
        resource_id: int = 0,
        risk_score: int = 0,
        **context: Any,
    ) -> Decision:
        """Evaluate a policy request. Always returns a Decision (fail-closed).

        Args:
            subject_id: Identifier for the subject (user, service, model).
            action: The action being requested.
            resource_id: Identifier for the target resource.
            risk_score: Numeric risk assessment (0-100 typical).
            **context: Additional context (currently unused by WASM evaluate).

        Returns:
            A Decision object. On any error, outcome is "Deny" (fail-closed).
        """
        try:
            result = self._evaluate_fn(
                self._store,
                subject_id,
                action,
                resource_id,
                risk_score,
            )
            self._eval_count += 1
            return Decision._from_i32(result)
        except Exception as e:
            # Fail-closed: any error produces Deny.
            self._eval_count += 1
            return Decision(outcome="Deny", error=str(e))

    def evaluate_dict(self, request: dict) -> Decision:
        """Evaluate from a dictionary.

        Args:
            request: Dict with keys subject_id, action, resource_id, risk_score.

        Returns:
            A Decision object.
        """
        return self.evaluate(
            subject_id=request.get("subject_id", 0),
            action=request.get("action", 0),
            resource_id=request.get("resource_id", 0),
            risk_score=request.get("risk_score", 0),
        )

    @property
    def audit_count(self) -> int:
        """Number of evaluations performed."""
        return self._eval_count

    @staticmethod
    def _compile_source(source: str) -> bytes:
        """Compile RUNE source to WASM using the rune-lang CLI."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src_path = Path(tmpdir) / "policy.rune"
            src_path.write_text(source, encoding="utf-8")

            try:
                subprocess.run(
                    ["rune-lang", "build", str(src_path)],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            except FileNotFoundError:
                raise RuneError(
                    "rune-lang CLI not found on PATH. "
                    "Install rune-lang or provide pre-compiled WASM bytes."
                ) from None
            except subprocess.CalledProcessError as e:
                raise RuneError(f"compilation failed: {e.stderr}") from e

            wasm_path = Path(tmpdir) / "policy.rune.wasm"
            if not wasm_path.exists():
                raise RuneError("compilation produced no output")
            return wasm_path.read_bytes()

    def __repr__(self) -> str:
        return f"PolicyEngine(evaluations={self._eval_count})"


def load(wasm_path: str) -> PolicyEngine:
    """Load a RUNE policy module from a .wasm file.

    Shorthand for PolicyEngine(wasm_path=path).

    Args:
        wasm_path: Path to a compiled .rune.wasm file.

    Returns:
        A PolicyEngine ready for evaluation.
    """
    return PolicyEngine(wasm_path=wasm_path)
