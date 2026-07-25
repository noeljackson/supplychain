#!/usr/bin/env python3
"""Fail CI when privileged release inputs or evidence requirements drift."""

from __future__ import annotations

import re
from pathlib import Path


WORKFLOW = Path(".github/workflows/release.yml")
CONFIG = Path(".goreleaser.yaml")


def require(pattern: str, body: str, message: str) -> None:
    if not re.search(pattern, body, re.MULTILINE):
        raise SystemExit(message)


def main() -> int:
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
