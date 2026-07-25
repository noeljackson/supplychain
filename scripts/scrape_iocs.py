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
    new = [e for e in entries if e.split("#", 1)[0].strip() not in have]
    if not new:
        return 0
    today = dt.date.today().isoformat()
    block = ["", f"# {header} (auto-added {today})"] + new + [""]
    with path.open("a") as f:
        f.write("\n".join(block))
    return len(new)


# ---------- GHSA via the gh CLI ----------


class SourceQueryError(RuntimeError):
    """Threat-intel query failed; this must not be reported as no changes."""


def gh_graphql(query: str, **variables):
    args = ["gh", "api", "graphql", "-f", f"query={query}"]
    for name, value in variables.items():
        if value is not None:
            args.extend(["-F", f"{name}={value}"])
    try:
        output = subprocess.run(
            args, capture_output=True, text=True, check=True, timeout=60,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise SourceQueryError(f"GHSA query failed: {exc}") from exc
    try:
        document = json.loads(output)
    except json.JSONDecodeError as exc:
        raise SourceQueryError("GHSA query returned invalid JSON") from exc
    if document.get("errors"):
        raise SourceQueryError(f"GHSA query returned errors: {document['errors']}")
    return document


def advisory_vulnerability_pages(ghsa_id: str, cursor: str) -> list[dict]:
    query = """
query($ghsaId: String!, $cursor: String!) {
  securityAdvisory(ghsaId: $ghsaId) {
    vulnerabilities(first: 100, after: $cursor, ecosystem: NPM) {
      pageInfo { hasNextPage endCursor }
      nodes {
        package { name }
        vulnerableVersionRange
      }
    }
  }
}
"""
    nodes: list[dict] = []
    while cursor:
        document = gh_graphql(query, ghsaId=ghsa_id, cursor=cursor)
        advisory = document.get("data", {}).get("securityAdvisory") or {}
        connection = advisory.get("vulnerabilities") or {}
        nodes.extend(connection.get("nodes") or [])
        page = connection.get("pageInfo") or {}
        cursor = page.get("endCursor") if page.get("hasNextPage") else ""
    return nodes


_GHSA_RE = re.compile(r"\bGHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}\b", re.I)


def tracked_ghsa_ids(paths: list[Path]) -> set[str]:
    """Return source advisory IDs recorded in IOC line comments."""
    ids: set[str] = set()
    for path in paths:
        if path.exists():
            ids.update(match.upper() for match in _GHSA_RE.findall(path.read_text()))
    return ids


def withdrawn_advisories(ids: set[str]) -> set[str]:
    """Resolve withdrawal state for tracked advisories, failing closed."""
    query = """
query($ghsaId: String!) {
  securityAdvisory(ghsaId: $ghsaId) {
    ghsaId
    withdrawnAt
  }
}
"""
    withdrawn: set[str] = set()
    for ghsa_id in sorted(ids):
        document = gh_graphql(query, ghsaId=ghsa_id)
        advisory = document.get("data", {}).get("securityAdvisory")
        if advisory is None:
            raise SourceQueryError(f"tracked advisory {ghsa_id} was not returned by GHSA")
        if advisory.get("withdrawnAt"):
            withdrawn.add(ghsa_id)
    return withdrawn


def remove_withdrawn_entries(path: Path, withdrawn: set[str]) -> int:
    """Remove IOC lines whose recorded source advisories are all withdrawn."""
    if not path.exists() or not withdrawn:
        return 0
    original = path.read_text()
    kept: list[str] = []
    removed = 0
    for raw in original.splitlines():
        source_ids = {match.upper() for match in _GHSA_RE.findall(raw)}
        if source_ids and source_ids.issubset(withdrawn):
            removed += 1
            continue
        kept.append(raw)
    if removed:
        path.write_text("\n".join(kept).rstrip() + "\n")
    return removed


def ghsa_npm_malware(since_days: int):
    """
    Query GHSA for npm-ecosystem MALWARE advisories published in the last
    `since_days` days. Returns:
      (
        pinned:  list of (name, version, ghsa_id) — concrete version pins,
        blocked: list of (name, ghsa_id) — "all versions affected" entries
                  with vulnerableVersionRange ">= 0".
      )
    Uses the `gh` CLI (assumed authed in the workflow). Source and pagination
    failures raise SourceQueryError so callers never confuse them with a clean
    no-change run.
    """
    cutoff = (dt.datetime.now(dt.UTC) - dt.timedelta(days=since_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    # `withdrawnAt` is fetched explicitly so we can drop retracted entries.
    # We don't use a top-level `withdrawn: false` argument because it isn't a
    # supported field on the securityAdvisories query. Example we were leaking
    # without this filter: GHSA-grrc-v84p-qwv3 ("Malware in
    # @puppeteer/browsers" 3.0.1) was published+retracted same-day, and the
    # legit Google-maintained @puppeteer/browsers ended up on the IOC list.
    query = """
query($cutoff: DateTime!, $cursor: String) {
  securityAdvisories(
    first: 100
    after: $cursor
    classifications: [MALWARE]
    publishedSince: $cutoff
    orderBy: { field: PUBLISHED_AT, direction: DESC }
  ) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ghsaId
      summary
      withdrawnAt
      vulnerabilities(first: 100, ecosystem: NPM) {
        pageInfo { hasNextPage endCursor }
        nodes {
          package { name }
          vulnerableVersionRange
        }
      }
    }
  }
}
"""
    pinned: list[tuple[str, str, str]] = []
    blocked: list[tuple[str, str]] = []
    withdrawn: set[str] = set()
    cursor = None
    while True:
        doc = gh_graphql(query, cutoff=cutoff, cursor=cursor)
        connection = doc.get("data", {}).get("securityAdvisories") or {}
        for adv in connection.get("nodes") or []:
            gid = adv.get("ghsaId", "")
            if adv.get("withdrawnAt"):
                if gid:
                    withdrawn.add(gid)
                continue
            vulnerabilities = adv.get("vulnerabilities") or {}
            vuln_nodes = list(vulnerabilities.get("nodes") or [])
            vuln_page = vulnerabilities.get("pageInfo") or {}
            if vuln_page.get("hasNextPage") and vuln_page.get("endCursor"):
                vuln_nodes.extend(advisory_vulnerability_pages(gid, vuln_page["endCursor"]))
            for vuln in vuln_nodes:
                name = (vuln.get("package") or {}).get("name", "")
                rng = (vuln.get("vulnerableVersionRange") or "").strip()
                if not name:
                    continue
                if _ALL_VERSIONS_RE.match(rng):
                    blocked.append((name, gid))
                    continue
                for ver in versions_from_range(rng):
                    pinned.append((name, ver, gid))
        page = connection.get("pageInfo") or {}
        if not page.get("hasNextPage") or not page.get("endCursor"):
            break
        cursor = page["endCursor"]
    return pinned, blocked, withdrawn


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
    args.report.parent.mkdir(parents=True, exist_ok=True)

    try:
        pinned, blocked, recently_withdrawn = ghsa_npm_malware(
            since_days=args.since_days,
        )
        tracked = tracked_ghsa_ids([args.packages, args.blocked])
        withdrawn = recently_withdrawn | withdrawn_advisories(tracked)
    except SourceQueryError as exc:
        summary.extend([
            "## Refresh failed",
            "",
            f"The GHSA source could not be queried completely: `{exc}`",
            "",
            "No IOC files were changed.",
        ])
        args.report.write_text("\n".join(summary) + "\n")
        print(str(exc), file=sys.stderr)
        return 2

    removed_pkg = remove_withdrawn_entries(args.packages, withdrawn)
    removed_block = remove_withdrawn_entries(args.blocked, withdrawn)

    # Pre-resolve npm status for every distinct package name being added, with
    # bounded concurrency so we don't hammer the registry.
    names_to_check = sorted({n for (n, _, _) in pinned} | {n for (n, _) in blocked})
    statuses = bulk_npm_status(names_to_check, workers=4)

    legend = (
        "_npm status legend: ✓ npm-confirmed (security-holder) · "
        "⚠ still-active · · unpublished (no holder) · ? unknown_"
    )

    # 1) concrete-version pins → iocs/packages.txt
    pkg_sources: dict[str, set[str]] = {}
    for name, version, ghsa_id in pinned:
        pkg_sources.setdefault(f"{name}@{version}", set()).add(ghsa_id)
    pkg_entries = [
        f"{entry} # {','.join(sorted(pkg_sources[entry]))}"
        for entry in sorted(pkg_sources)
    ]
    added_pkg = append(
        args.packages, pkg_entries,
        f"GHSA MALWARE advisories — version pins (npm, last {args.since_days}d)",
    )
    summary.append(
        f"## packages.txt — +{added_pkg}/-{removed_pkg} "
        f"(out of {len(pinned)} pin entries returned)"
    )
    summary.append(legend)
    if added_pkg:
        for (n, v, gid) in sorted(set(pinned)):
            if f"{n}@{v}" in pkg_sources:
                icon = _STATUS_ICON.get(statuses.get(n, "unknown"), "?")
                summary.append(f"- {icon} `{n}@{v}` ([{gid}](https://github.com/advisories/{gid}))")

    # 2) all-versions advisories → iocs/blocked-package-names.txt
    block_sources: dict[str, set[str]] = {}
    for name, ghsa_id in blocked:
        block_sources.setdefault(name, set()).add(ghsa_id)
    block_names = sorted(block_sources)
    block_entries = [
        f"{name} # {','.join(sorted(block_sources[name]))}"
        for name in block_names
    ]
    added_block = append(
        args.blocked, block_entries,
        f"GHSA MALWARE advisories — all-versions ranges (npm, last {args.since_days}d)",
    )
    summary.append("")
    summary.append(
        f"## blocked-package-names.txt — +{added_block}/-{removed_block} "
        f"(out of {len(blocked)} all-versions entries)"
    )
    summary.append(legend)
    if added_block:
        # Status summary line first, then full per-entry list.
        from collections import Counter
        counts = Counter(statuses.get(n, "unknown") for n in block_names)
        summary.append(
            "  status breakdown: "
            + ", ".join(f"{_STATUS_ICON[k]} {k} {v}" for k, v in counts.most_common())
        )
        for n in block_names:
            gids = sorted(block_sources[n])
            gid = gids[0]
            icon = _STATUS_ICON.get(statuses.get(n, "unknown"), "?")
            links = ", ".join(
                f"[{source}](https://github.com/advisories/{source})"
                for source in gids
            )
            summary.append(f"- {icon} `{n}` ({links})")

    summary.append("")
    summary.append("## persistence-paths.txt — +0 (no scraper wired yet)")
    summary.append("## payload-filenames.txt  — +0 (no scraper wired yet)")

    args.report.write_text("\n".join(summary) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
