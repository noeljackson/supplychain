#!/usr/bin/env python3
"""Enforce focused floors for security-critical Go packages."""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path


# Floors sit below the current hermetic suite so they catch meaningful
# regressions without making harmless compiler/control-flow changes brittle.
# Command orchestration has the lowest floor because most branches write
# directly to process stdio; parser/trust-boundary packages are held higher.
FLOORS = {
    "./cmd": 15.0,
    "./internal/artifact": 65.0,
    "./internal/audit": 40.0,
    "./internal/bunverify": 35.0,
    "./internal/ioc": 45.0,
    "./internal/manifest": 75.0,
    "./internal/osv": 40.0,
    "./internal/policy": 70.0,
    "./internal/report": 50.0,
    "./internal/scan": 55.0,
    "./internal/secrets": 70.0,
    "./internal/update": 42.0,
}


def package_coverage(package: str) -> float:
    with tempfile.TemporaryDirectory(prefix="supplychain-coverage-") as tmp:
        profile = Path(tmp) / "coverage.out"
        subprocess.run(
            ["go", "test", package, f"-coverprofile={profile}"],
            check=True,
        )
        output = subprocess.run(
            ["go", "tool", "cover", f"-func={profile}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    match = re.search(r"^total:\s+\(statements\)\s+([0-9.]+)%$", output, re.MULTILINE)
    if not match:
        raise SystemExit(f"could not parse coverage for {package}")
    return float(match.group(1))


def main() -> int:
    failures: list[str] = []
    for package, floor in FLOORS.items():
        actual = package_coverage(package)
        print(f"{package}: {actual:.1f}% (floor {floor:.1f}%)")
        if actual < floor:
            failures.append(f"{package}: {actual:.1f}% < {floor:.1f}%")
    if failures:
        raise SystemExit("coverage floors failed:\n" + "\n".join(failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
