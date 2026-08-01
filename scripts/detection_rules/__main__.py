"""
detection_rules.__main__
========================

Dispatcher for `python -m detection_rules <command>`.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import __version__
from .commands import (
    atomic,
    badges,
    coverage,
    cti,
    fix,
    gap,
    heatmap,
    index,
    lint,
    lint_severity,
    metrics,
    navigator,
    new,
    test,
)

COMMANDS = {
    "coverage":       coverage,
    "index":          index,
    "fix":            fix,
    "lint":           lint,
    "lint-severity":  lint_severity,
    "metrics":        metrics,
    "navigator":      navigator,
    "new":            new,
    "gap":            gap,
    "cti":            cti,
    "atomic":         atomic,
    "test":           test,
    "badges":         badges,
    "heatmap":        heatmap,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detection_rules",
        description="Unified tooling for the Detection-Rules repository.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    for name, mod in COMMANDS.items():
        cmd_parser = sub.add_parser(name, help=mod.__doc__.strip().splitlines()[0])
        mod.add_arguments(cmd_parser)
        cmd_parser.set_defaults(_handler=mod.run)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args._handler(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
