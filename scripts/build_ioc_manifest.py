#!/usr/bin/env python3
"""Build the checksummed IOC snapshot manifest consumed by the updater."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path


IOC_FILES = (
    "persistence-paths.txt",
    "payload-filenames.txt",
    "packages.txt",
    "c2-domains.txt",
    "dead-drop-signatures.txt",
    "blocked-package-names.txt",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iocs-dir", type=Path, default=Path("iocs"))
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()

    files: dict[str, dict[str, object]] = {}
    for name in IOC_FILES:
        path = args.iocs_dir / name
        body = path.read_bytes()
        if not body.strip():
            raise SystemExit(f"{path} is empty")
        files[name] = {
            "sha256": hashlib.sha256(body).hexdigest(),
            "size": len(body),
        }

    manifest = {
        "schema_version": 1,
        "generated_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "source_revision": args.source_revision,
        "files": dict(sorted(files.items())),
    }
    output = args.iocs_dir / "manifest.json"
    output.write_text(json.dumps(manifest, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
