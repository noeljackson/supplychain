#!/usr/bin/env python3
"""Fail-closed policy for unattended Dependabot Go patch updates."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


UPDATE = re.compile(
    r"^Updates `(?P<module>[^`]+)` from v?(?P<old>\d+\.\d+\.\d+) "
    r"to v?(?P<new>\d+\.\d+\.\d+)$",
    re.MULTILINE,
)
EXPECTED_FILES = {"go.mod", "go.sum"}


def parse_version(value: str) -> tuple[int, int, int]:
    return tuple(int(part) for part in value.removeprefix("v").split("."))  # type: ignore[return-value]


def is_direct_requirement(go_mod: str, module: str, version: str) -> bool:
    """Return whether go.mod requires exactly module@version without indirect."""
    in_require_block = False
    for raw_line in go_mod.splitlines():
        line = raw_line.strip()
        if line == "require (":
            in_require_block = True
            continue
        if in_require_block and line == ")":
            in_require_block = False
            continue

        if line.startswith("require "):
            line = line.removeprefix("require ").strip()
        elif not in_require_block:
            continue

        dependency, _, comment = line.partition("//")
        parts = dependency.split()
        if len(parts) == 2 and parts[0] == module and parts[1] == f"v{version}":
            return "indirect" not in comment
    return False


def classify(body: str, go_mod: str, changed_files: list[str]) -> tuple[bool, str]:
    """Accept one direct Go-module patch update with no unrelated files."""
    if len(changed_files) != 2 or set(changed_files) != EXPECTED_FILES:
        return False, "changed files are not exactly go.mod and go.sum"

    updates = list(UPDATE.finditer(body))
    if len(updates) != 1:
        return False, "pull request does not contain exactly one stable version update"

    update = updates[0]
    old_version = parse_version(update["old"])
    new_version = parse_version(update["new"])
    if old_version[:2] != new_version[:2] or new_version[2] <= old_version[2]:
        return False, "update is not a forward SemVer patch"

    if not is_direct_requirement(go_mod, update["module"], update["new"]):
        return False, "updated module is not a direct requirement at the expected version"

    return True, f"direct patch update for {update['module']}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--body", type=Path, required=True)
    parser.add_argument("--go-mod", type=Path, required=True)
    parser.add_argument("--changed-files", type=Path, required=True)
    args = parser.parse_args()

    eligible, reason = classify(
        args.body.read_text(),
        args.go_mod.read_text(),
        [line for line in args.changed_files.read_text().splitlines() if line],
    )
    print(f"eligible={str(eligible).lower()}")
    print(f"reason={reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
