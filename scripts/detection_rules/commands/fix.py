"""Backfill MITRE ATT&CK metadata in rules (replaces fix_*.py scripts)."""

from __future__ import annotations

from argparse import ArgumentParser, Namespace

from .._fixers import (
    fix_carbonblack,
    fix_sentinel,
    fix_wazuh,
    improve_sigma_fp,
)


PLATFORM_FIXERS = {
    "carbonblack": fix_carbonblack,
    "sentinel":    fix_sentinel,
    "wazuh":       fix_wazuh,
    "sigma-fp":    improve_sigma_fp,
}


def add_arguments(parser: ArgumentParser) -> None:
    parser.add_argument(
        "platform",
        choices=list(PLATFORM_FIXERS.keys()) + ["all"],
        help="Platform to fix, or 'all' to run every fixer in sequence.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would change without writing files.",
    )


def run(args: Namespace) -> int:
    targets = (
        list(PLATFORM_FIXERS.values()) if args.platform == "all"
        else [PLATFORM_FIXERS[args.platform]]
    )
    rc = 0
    for fixer in targets:
        rc |= int(fixer(dry_run=args.dry_run) or 0)
    return rc
