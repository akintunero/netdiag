"""Stable exit codes for automation and runbooks.

See docs/CLI_CONTRACT.md - these values are stable from v0.1 onward.
"""

from __future__ import annotations

EX_OK = 0
"""Success; probes completed (individual check steps may still show FAIL in output)."""

EX_FAIL = 1
"""Target or check failed (unreachable, closed port, health check FAIL, etc.)."""

EX_ERROR = 2
"""User error, missing required tooling, or command could not run."""
