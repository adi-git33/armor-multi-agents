"""
Shared helpers for all validation scripts.

Provides:
  - ValidationResult  — holds one check's outcome
  - ValidationSuite   — collects results and prints a summary
  - header / check    — printing utilities
"""

from __future__ import annotations
import contextvars
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional


# ── live result-streaming hook (used by validation/api.py) ────────────
# A ValidationSuite normally just accumulates results and prints them at
# the end (see print_results()). The web API needs to push each check to
# connected browsers AS it happens (some suites run for over a minute),
# without validate_*.py files knowing anything about HTTP/WebSockets.
# ContextVar rather than a module global: safe if suites ever run
# concurrently in the same process, and a no-op (default None) for every
# existing CLI call site.
_on_result_cv: "contextvars.ContextVar[Optional[Callable[[ValidationResult], None]]]" = (
    contextvars.ContextVar("on_result", default=None)
)


def set_result_callback(cb: Callable[["ValidationResult"], None]) -> contextvars.Token:
    """Register a callback invoked synchronously on every suite.check()/add().
    Returns a token — pass it to reset_result_callback() when done."""
    return _on_result_cv.set(cb)


def reset_result_callback(token: contextvars.Token) -> None:
    _on_result_cv.reset(token)


# ── colours (disabled when not a tty) ─────────────────────────────────
_TTY = sys.stdout.isatty()
GREEN  = "\033[92m" if _TTY else ""
RED    = "\033[91m" if _TTY else ""
YELLOW = "\033[93m" if _TTY else ""
CYAN   = "\033[96m" if _TTY else ""
BOLD   = "\033[1m"  if _TTY else ""
RESET  = "\033[0m"  if _TTY else ""


@dataclass
class ValidationResult:
    """One atomic check."""
    req_id:   str          # e.g. "FR-01"
    label:    str          # human description
    passed:   bool
    observed: Any = None   # what the system produced
    expected: Any = None   # what the SRS/SDD requires
    note:     str = ""     # optional extra context

    @property
    def status(self) -> str:
        return f"{GREEN}PASS{RESET}" if self.passed else f"{RED}FAIL{RESET}"


class ValidationSuite:
    """Collects ValidationResults and prints a table."""

    def __init__(self, title: str) -> None:
        self.title   = title
        self.results: list[ValidationResult] = []
        self.metrics: dict[str, Any] = {}
        self._t0     = time.monotonic()

    def set_metrics(self, data: Mapping[str, Any]) -> None:
        """Merge structured chart/export data produced by this suite."""
        self.metrics.update(data)

    def add(self, result: ValidationResult) -> None:
        self.results.append(result)
        cb = _on_result_cv.get()
        if cb:
            cb(result)

    def check(
        self,
        req_id:   str,
        label:    str,
        passed:   bool,
        observed: Any = None,
        expected: Any = None,
        note:     str = "",
    ) -> ValidationResult:
        r = ValidationResult(req_id, label, passed, observed, expected, note)
        self.results.append(r)
        cb = _on_result_cv.get()
        if cb:
            cb(r)
        return r

    # ── printing ───────────────────────────────────────────────────────

    def print_results(self) -> None:
        elapsed = time.monotonic() - self._t0
        passed  = sum(1 for r in self.results if r.passed)
        total   = len(self.results)
        all_ok  = passed == total

        w = 70
        print(f"\n{'=' * w}")
        print(f"  {BOLD}{self.title}{RESET}")
        print(f"{'=' * w}")

        for r in self.results:
            mark = f"[{r.status}]"
            print(f"\n  {mark} {CYAN}{r.req_id}{RESET}  {r.label}")
            if r.observed is not None or r.expected is not None:
                obs = _fmt(r.observed)
                exp = _fmt(r.expected)
                print(f"         observed={obs}   expected={exp}")
            if r.note:
                print(f"         note: {r.note}")

        verdict_color = GREEN if all_ok else RED
        print(f"\n{'─' * w}")
        print(
            f"  {verdict_color}{BOLD}{'ALL PASS' if all_ok else 'SOME FAILURES'}{RESET}"
            f"  ({passed}/{total} checks passed,  {elapsed:.2f}s)"
        )
        print(f"{'=' * w}\n")

    @property
    def all_passed(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def total_count(self) -> int:
        return len(self.results)


def _fmt(v: Any) -> str:
    if v is None:
        return "—"
    if isinstance(v, float):
        return f"{v:.4f}"
    return str(v)


def section(title: str) -> None:
    print(f"\n  {BOLD}{YELLOW}── {title}{RESET}")
