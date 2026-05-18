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
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


# ---------- npm "security holder" enrichment ----------

# When npm staff confirm a package is malicious and pull it, the registry slot
# is replaced with a stub matching this exact shape. Detecting it gives us a
# stronger trust signal than the GHSA classification alone — independent
# verification that an org separate from the GHSA reporter has acted.
_SEC_HOLDER_REPO = "npm/security-holder"
_SEC_HOLDER_LATEST = "0.0.1-security"


def npm_status(name: str, timeout: float = 8.0) -> str:
    """Return one of: 'npm-confirmed', 'still-active', 'unpublished', 'unknown'.

    'npm-confirmed' = registry shows a security-holder placeholder.
    'still-active'  = package is live with real metadata.
    'unpublished'   = 404 (package was removed but no holder placed yet).
    'unknown'       = transient failure; reviewer should re-check manually.
    """
    # url-encode scoped names
    enc = name.replace("/", "%2F") if name.startswith("@") else name
    url = f"https://registry.npmjs.org/{enc}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.loads(r.read())
    except urllib.error.HTTPError as e:
        return "unpublished" if e.code == 404 else "unknown"
    except Exception:
        return "unknown"

    latest = (d.get("dist-tags") or {}).get("latest", "")
    desc = d.get("description", "")
    repo = d.get("repository")
    if isinstance(repo, dict):
        repo = repo.get("url", "")
    if latest == _SEC_HOLDER_LATEST or repo == _SEC_HOLDER_REPO or desc == "security holding package":
        return "npm-confirmed"
    return "still-active"


def bulk_npm_status(names: list[str], workers: int = 4) -> dict[str, str]:
    """Resolve npm_status for each name with bounded concurrency."""
    out: dict[str, str] = {}
    if not names:
        return out
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for name, status in zip(names, ex.map(npm_status, names)):
            out[name] = status
    return out


_STATUS_ICON = {
    "npm-confirmed": "✓",
    "still-active":  "⚠",
    "unpublished":   "·",
    "unknown":       "?",
}


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

def ghsa_npm_malware(since_days: int):
    """
    Query GHSA for npm-ecosystem MALWARE advisories published in the last
    `since_days` days. Returns:
      (
        pinned:  list of (name, version, ghsa_id) — concrete version pins,
        blocked: list of (name, ghsa_id) — "all versions affected" entries
                  with vulnerableVersionRange ">= 0".
      )
    Uses the `gh` CLI (assumed authed in the workflow). Falls back to empty
    on any failure — never raises.
    """
    cutoff = (dt.datetime.utcnow() - dt.timedelta(days=since_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    # `withdrawnAt` is fetched explicitly so we can drop retracted entries.
    # We don't use a top-level `withdrawn: false` argument because it isn't a
    # supported field on the securityAdvisories query. Example we were leaking
    # without this filter: GHSA-grrc-v84p-qwv3 ("Malware in
    # @puppeteer/browsers" 3.0.1) was published+retracted same-day, and the
    # legit Google-maintained @puppeteer/browsers ended up on the IOC list.
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
      withdrawnAt
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
        return [], []

    try:
        doc = json.loads(out)
    except json.JSONDecodeError:
        return [], []

    pinned: list[tuple[str, str, str]] = []
    blocked: list[tuple[str, str]] = []
    for adv in doc.get("data", {}).get("securityAdvisories", {}).get("nodes", []) or []:
        # Belt-and-suspenders: drop withdrawn entries client-side too, even
        # though the GraphQL filter should have excluded them.
        if adv.get("withdrawnAt"):
            continue
        gid = adv.get("ghsaId", "")
        for vuln in (adv.get("vulnerabilities") or {}).get("nodes", []) or []:
            name = (vuln.get("package") or {}).get("name", "")
            rng  = (vuln.get("vulnerableVersionRange") or "").strip()
            if not name:
                continue
            if _ALL_VERSIONS_RE.match(rng):
                blocked.append((name, gid))
                continue
            for ver in versions_from_range(rng):
                pinned.append((name, ver, gid))
    return pinned, blocked


# Matches the canonical "all versions affected" range emitted by GHSA when a
# package has no clean version: ">= 0" (with optional spaces). This is the
# overwhelming majority of MAL-* advisories — packages published purely
# for malice.
_ALL_VERSIONS_RE = re.compile(r"^>=\s*0(?:\.0(?:\.0)?)?$")
_VER_RE = re.compile(r"\b\d+\.\d+\.\d+(?:-[A-Za-z0-9.\-]+)?\b")

def versions_from_range(rng: str) -> list[str]:
    """
    Extract specific versions from a vulnerableVersionRange like '= 1.161.11'.
    Only handles single-version pins (`= X.Y.Z`). Broader ranges and "all
    versions" entries are handled by ALL_VERSIONS_RE in the caller.
    """
    s = rng.strip()
    if not s.startswith("="):
        return []
    m = _VER_RE.findall(s)
    return m[:1] if m else []


# ---------- main ----------

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--packages",     type=Path, required=True)
    p.add_argument("--blocked",      type=Path, required=True)
    p.add_argument("--persistence",  type=Path, required=True)
    p.add_argument("--payloads",     type=Path, required=True)
    p.add_argument("--report",       type=Path, required=True)
    p.add_argument("--since-days",   type=int,  default=14)
    args = p.parse_args()

    summary: list[str] = ["# IOC refresh report", ""]

    pinned, blocked = ghsa_npm_malware(since_days=args.since_days)

    # Pre-resolve npm status for every distinct package name being added, with
    # bounded concurrency so we don't hammer the registry.
    names_to_check = sorted({n for (n, _, _) in pinned} | {n for (n, _) in blocked})
    statuses = bulk_npm_status(names_to_check, workers=4)

    legend = (
        "_npm status legend: ✓ npm-confirmed (security-holder) · "
        "⚠ still-active · · unpublished (no holder) · ? unknown_"
    )

    # 1) concrete-version pins → iocs/packages.txt
    pkg_entries = sorted({f"{n}@{v}" for (n, v, _) in pinned})
    added_pkg = append(
        args.packages, pkg_entries,
        f"GHSA MALWARE advisories — version pins (npm, last {args.since_days}d)",
    )
    summary.append(f"## packages.txt — +{added_pkg} (out of {len(pinned)} pin entries returned)")
    summary.append(legend)
    if added_pkg:
        for (n, v, gid) in sorted(set(pinned)):
            if f"{n}@{v}" in pkg_entries:
                icon = _STATUS_ICON.get(statuses.get(n, "unknown"), "?")
                summary.append(f"- {icon} `{n}@{v}` ([{gid}](https://github.com/advisories/{gid}))")

    # 2) all-versions advisories → iocs/blocked-package-names.txt
    block_entries = sorted({n for (n, _) in blocked})
    added_block = append(
        args.blocked, block_entries,
        f"GHSA MALWARE advisories — all-versions ranges (npm, last {args.since_days}d)",
    )
    summary.append("")
    summary.append(f"## blocked-package-names.txt — +{added_block} (out of {len(blocked)} all-versions entries)")
    summary.append(legend)
    if added_block:
        # Status summary line first, then full per-entry list.
        from collections import Counter
        counts = Counter(statuses.get(n, "unknown") for n in block_entries)
        summary.append(
            "  status breakdown: "
            + ", ".join(f"{_STATUS_ICON[k]} {k} {v}" for k, v in counts.most_common())
        )
        per_name_ids = {}
        for (n, gid) in blocked:
            per_name_ids.setdefault(n, gid)
        for n in block_entries:
            gid = per_name_ids.get(n, "")
            icon = _STATUS_ICON.get(statuses.get(n, "unknown"), "?")
            summary.append(f"- {icon} `{n}` ([{gid}](https://github.com/advisories/{gid}))")

    summary.append("")
    summary.append("## persistence-paths.txt — +0 (no scraper wired yet)")
    summary.append("## payload-filenames.txt  — +0 (no scraper wired yet)")

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(summary))

    if added_pkg == 0 and added_block == 0:
        return 1  # workflow uses this to short-circuit
    return 0


if __name__ == "__main__":
    sys.exit(main())
