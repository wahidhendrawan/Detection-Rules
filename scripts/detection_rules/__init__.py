"""
detection_rules
===============

Unified CLI for the Detection-Rules repository.

Replaces ad-hoc scripts (`fix_*.py`, `improve_*.py`, etc.) with a single
entrypoint exposing reproducible, well-tested subcommands.

Usage::

    python -m detection_rules <command> [options]

Available commands:
  coverage    Generate COVERAGE.md and coverage.json (ATT&CK Navigator).
  index       Generate rules.index.json / rules.index.yaml.
  fix         Backfill MITRE ATT&CK metadata in a given platform.
  lint        Validate Sigma syntax, structure, and required metadata offline.
  metrics     Compute Detection-as-Code quality metrics (per rule + summary).
  navigator   Emit ATT&CK Navigator layers (overall + per platform).
  gap         Report top ATT&CK techniques NOT yet covered.
  cti         Tag rules with threat actor / campaign references.
  atomic      Map rules to Atomic Red Team tests for end-to-end verification.
  test        Run rule unit tests (event fixture based).
  badges      Emit shields.io endpoint JSONs for live README badges.
  heatmap     Generate standalone accessible ATT&CK coverage heatmap HTML/JSON.
"""

from __future__ import annotations

__version__ = "0.1.0"
