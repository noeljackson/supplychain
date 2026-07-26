#!/usr/bin/env python3
"""Hermetic tests for IOC refresh source/error/provenance behavior."""

from __future__ import annotations

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

import scrape_iocs


class ScrapeIOCTest(unittest.TestCase):
    def test_report_is_bounded_without_splitting_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.md"
            scrape_iocs.write_report(
                path,
                ["# report"] + [f"- package-{index} \N{CHECK MARK}" for index in range(100)],
                max_bytes=512,
            )
            body = path.read_text()
            self.assertLessEqual(len(body.encode("utf-8")), 512)
            self.assertTrue(body.startswith("# report\n"))
            self.assertIn("Report truncated", body)
            self.assertIn("Review the complete IOC file diff", body)

    def test_append_deduplicates_inline_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "packages.txt"
            path.write_text("demo@1.0.0 # GHSA-old\n")
            added = scrape_iocs.append(
                path,
                [
                    "demo@1.0.0 # GHSA-new",
                    "new@2.0.0 # GHSA-source",
                ],
                "fixture",
            )
            self.assertEqual(added, 1)
            self.assertEqual(path.read_text().count("demo@1.0.0"), 1)
            self.assertIn("new@2.0.0 # GHSA-source", path.read_text())

    def test_withdrawal_removes_only_fully_withdrawn_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "packages.txt"
            path.write_text(
                "gone@1.0.0 # GHSA-2345-2345-2345\n"
                "kept@1.0.0 # GHSA-2345-2345-2345,GHSA-3456-3456-3456\n"
                "manual@1.0.0\n"
            )
            removed = scrape_iocs.remove_withdrawn_entries(
                path, {"GHSA-2345-2345-2345"},
            )
            self.assertEqual(removed, 1)
            body = path.read_text()
            self.assertNotIn("gone@", body)
            self.assertIn("kept@", body)
            self.assertIn("manual@", body)

    def test_source_failure_is_not_reported_as_no_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = {
                name: root / name
                for name in ("packages", "blocked", "persistence", "payloads", "report")
            }
            for name, path in paths.items():
                if name != "report":
                    path.write_text("fixture\n")
            argv = [
                "scrape_iocs.py",
                "--packages", str(paths["packages"]),
                "--blocked", str(paths["blocked"]),
                "--persistence", str(paths["persistence"]),
                "--payloads", str(paths["payloads"]),
                "--report", str(paths["report"]),
            ]
            before = {name: path.read_text() for name, path in paths.items() if name != "report"}
            with mock.patch.object(sys, "argv", argv), mock.patch.object(
                scrape_iocs,
                "ghsa_npm_malware",
                side_effect=scrape_iocs.SourceQueryError("fixture outage"),
            ), redirect_stderr(io.StringIO()):
                self.assertEqual(scrape_iocs.main(), 2)
            after = {name: path.read_text() for name, path in paths.items() if name != "report"}
            self.assertEqual(before, after)
            self.assertIn("Refresh failed", paths["report"].read_text())

    def test_advisory_and_vulnerability_connections_are_paginated(self) -> None:
        advisory_page_one = {
            "data": {
                "securityAdvisories": {
                    "pageInfo": {"hasNextPage": True, "endCursor": "advisory-2"},
                    "nodes": [{
                        "ghsaId": "GHSA-2345-2345-2345",
                        "withdrawnAt": None,
                        "vulnerabilities": {
                            "pageInfo": {"hasNextPage": True, "endCursor": "vuln-2"},
                            "nodes": [{
                                "package": {"name": "all-one"},
                                "vulnerableVersionRange": ">= 0",
                            }],
                        },
                    }],
                },
            },
        }
        vulnerability_page_two = {
            "data": {
                "securityAdvisory": {
                    "vulnerabilities": {
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                        "nodes": [{
                            "package": {"name": "pinned"},
                            "vulnerableVersionRange": "= 1.2.3",
                        }],
                    },
                },
            },
        }
        advisory_page_two = {
            "data": {
                "securityAdvisories": {
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "nodes": [{
                        "ghsaId": "GHSA-3456-3456-3456",
                        "withdrawnAt": None,
                        "vulnerabilities": {
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                            "nodes": [{
                                "package": {"name": "all-two"},
                                "vulnerableVersionRange": ">= 0.0.0",
                            }],
                        },
                    }],
                },
            },
        }
        with mock.patch.object(
            scrape_iocs,
            "gh_graphql",
            side_effect=[
                advisory_page_one,
                vulnerability_page_two,
                advisory_page_two,
            ],
        ) as graphql:
            pinned, blocked, withdrawn = scrape_iocs.ghsa_npm_malware(14)
        self.assertEqual(
            pinned,
            [("pinned", "1.2.3", "GHSA-2345-2345-2345")],
        )
        self.assertEqual(
            blocked,
            [
                ("all-one", "GHSA-2345-2345-2345"),
                ("all-two", "GHSA-3456-3456-3456"),
            ],
        )
        self.assertEqual(withdrawn, set())
        self.assertEqual(graphql.call_count, 3)


if __name__ == "__main__":
    unittest.main()
