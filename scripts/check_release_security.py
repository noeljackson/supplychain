#!/usr/bin/env python3
"""Fail CI when privileged release or scan inputs, or evidence requirements, drift."""

from __future__ import annotations

import re
from pathlib import Path


WORKFLOW = Path(".github/workflows/release.yml")
CONFIG = Path(".goreleaser.yaml")
SCAN_WORKFLOW = Path(".github/workflows/scan.yml")


def require(pattern: str, body: str, message: str) -> None:
    if not re.search(pattern, body, re.MULTILINE):
        raise SystemExit(message)


def check_scan_action_pin() -> None:
    """The reusable scan workflow must fetch its action source from a literal pin.

    An expression here is not merely unpinned. Inside a reusable workflow the
    github context describes the caller, and an expression that resolves to the
    empty string makes actions/checkout fall back to the caller's repository at
    its default branch, which the following step then executes as the scanner.
    """
    body = SCAN_WORKFLOW.read_text()
    pin = re.search(
        r"^\s*repository:\s*(\S+)[ \t]*$\n\s*ref:\s*(\S+)[ \t]*$",
        body,
        re.MULTILINE,
    )
    if pin is None:
        raise SystemExit(
            "scan.yml must check out the action source with literal repository and ref"
        )
    repository, ref = pin.group(1), pin.group(2)
    if repository != "noeljackson/supplychain":
        raise SystemExit(
            f"scan.yml action source repository must be a literal owner/repo: {repository}"
        )
    if not re.fullmatch(r"[0-9a-f]{40}", ref):
        raise SystemExit(
            f"scan.yml action source ref must be a full commit SHA: {ref}"
        )


def main() -> int:
    check_scan_action_pin()
    body = WORKFLOW.read_text()
    config = CONFIG.read_text()
    for reference in re.findall(r"^\s*uses:\s*(\S+)\s*(?:#.*)?$", body, re.MULTILINE):
        if not re.search(r"@[0-9a-f]{40}$", reference):
            raise SystemExit(f"release action must use a full commit SHA: {reference}")
    require(
        r"^\s+version:\s+v\d+\.\d+\.\d+\s*$",
        body,
        "release GoReleaser version must be an exact vMAJOR.MINOR.PATCH",
    )
    require(
        r"^\s+syft-version:\s+v\d+\.\d+\.\d+\s*$",
        body,
        "release Syft version must be an exact vMAJOR.MINOR.PATCH",
    )
    require(
        r"^\s+environment:\s+release\s*$",
        body,
        "release job must use the protected release environment",
    )
    for subject in ("dist/*.tar.gz", "dist/checksums.txt", "dist/*.sbom.*"):
        if subject not in body:
            raise SystemExit(f"release attestation is missing subject {subject}")
    require(
        r"^sboms:\s*\n(?:.*\n)*?\s+artifacts:\s+archive\s*$",
        config,
        "GoReleaser must generate an SBOM for release archives",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
