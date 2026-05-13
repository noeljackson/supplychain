#!/usr/bin/env python3
"""
IOC scraper for the ioc-refresh workflow (#13).

Polls public threat-intel sources for newly-disclosed supply-chain IOCs and
appends any new entries to iocs/{packages,persistence-paths,payload-filenames}.txt.
Writes a human-readable summary to --report.

Conservative by design: only adds entries we can confidently extract. The
workflow opens a PR for human review — never auto-merges.

Currently wired sources:
  - GitHub Advisory Database (GHSA) — npm-ecosystem advisories classified
    as MALWARE, published in the last N days.

Stub-but-ready sources (commented out below until per-source parsers land):
  - StepSecurity Harden-Runner blog RSS
  - Socket.dev research feed
  - Aikido Security blog
  - OpenSSF Package Analysis daily summary
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path


def existing_lines(path: Path) -> set[str]:
    if not path.exists():
        return set()
    out = set()
    for raw in path.read_text().splitlines():
        s = raw.split("#", 1)[0].strip()
        if s:
            out.add(s)
    return out


def append(path: Path, entries: list[str], header: str) -> int:
    """Append unique entries with a dated comment header. Returns count added."""
    have = existing_lines(path)
    new = [e for e in entries if e not in have]
    if not new:
        return 0
    today = dt.date.today().isoformat()
    block = ["", f"# {header} (auto-added {today})"] + new + [""]
    with path.open("a") as f:
        f.write("\n".join(block))
    return len(new)


# ---------- GHSA via the gh CLI ----------

def ghsa_npm_malware(since_days: int) -> list[tuple[str, str, str]]:
    """
    Returns (name, version, ghsa_id) tuples from npm-ecosystem advisories
    classified as MALWARE, published in the last `since_days` days.

    Uses the `gh` CLI (assumed authed in the workflow). Falls back to an
    empty list on failure — never raises.
    """
    cutoff = (dt.datetime.utcnow() - dt.timedelta(days=since_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    query = """
query($cutoff: DateTime!) {
  securityAdvisories(
    first: 100
    classifications: [MALWARE]
    publishedSince: $cutoff
    orderBy: { field: PUBLISHED_AT, direction: DESC }
  ) {
    nodes {
      ghsaId
      summary
      vulnerabilities(first: 50, ecosystem: NPM) {
        nodes {
          package { name }
          vulnerableVersionRange
        }
      }
    }
  }
}
"""
    try:
        out = subprocess.run(
            ["gh", "api", "graphql",
             "-f", f"query={query}",
             "-F", f"cutoff={cutoff}"],
            capture_output=True, text=True, check=True, timeout=60,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"warn: ghsa query failed: {e}", file=sys.stderr)
        return []

    try:
        doc = json.loads(out)
    except json.JSONDecodeError:
        return []

    found: list[tuple[str, str, str]] = []
    for adv in doc.get("data", {}).get("securityAdvisories", {}).get("nodes", []) or []:
        gid = adv.get("ghsaId", "")
        for vuln in (adv.get("vulnerabilities") or {}).get("nodes", []) or []:
            name = (vuln.get("package") or {}).get("name", "")
            rng  = vuln.get("vulnerableVersionRange") or ""
            for ver in versions_from_range(rng):
                if name and ver:
                    found.append((name, ver, gid))
    return found


_VER_RE = re.compile(r"\b\d+\.\d+\.\d+(?:-[A-Za-z0-9.\-]+)?\b")

def versions_from_range(rng: str) -> list[str]:
    """
    Extract specific versions referenced in a vulnerableVersionRange string
    like '= 1.161.11' or '>= 1.161.11, < 1.161.15'. We only emit IOC
    entries for ranges that pin a single version (e.g. '= 1.161.11'),
    since broader ranges can match benign earlier versions.
    """
    s = rng.strip()
    if not s.startswith("="):
        return []
    m = _VER_RE.findall(s)
    return m[:1] if m else []


# ---------- main ----------

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--packages",    type=Path, required=True)
    p.add_argument("--persistence", type=Path, required=True)
    p.add_argument("--payloads",    type=Path, required=True)
    p.add_argument("--report",      type=Path, required=True)
    p.add_argument("--since-days",  type=int,  default=14)
    args = p.parse_args()

    summary: list[str] = ["# IOC refresh report", ""]

    ghsa_hits = ghsa_npm_malware(since_days=args.since_days)
    pkg_entries = [f"{n}@{v}" for (n, v, _) in ghsa_hits]
    added_pkg = append(
        args.packages, pkg_entries,
        f"GHSA MALWARE advisories (npm, last {args.since_days}d)",
    )
    summary.append(f"## packages.txt — +{added_pkg}")
    if added_pkg:
        for (n, v, gid) in ghsa_hits:
            if f"{n}@{v}" in pkg_entries:
                summary.append(f"- `{n}@{v}` ([{gid}](https://github.com/advisories/{gid}))")
    summary.append("")
    summary.append("## persistence-paths.txt — +0 (no scraper wired yet)")
    summary.append("## payload-filenames.txt — +0 (no scraper wired yet)")

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(summary))

    total = added_pkg
    if total == 0:
        return 1  # workflow uses this to short-circuit
    return 0


if __name__ == "__main__":
    sys.exit(main())
