import unittest

from classify_dependabot_update import classify


DIRECT_GO_MOD = """module example.com/supplychain

require (
	github.com/acme/direct v1.2.4
	github.com/acme/indirect v1.2.4 // indirect
)
"""


class ClassifyDependabotUpdateTest(unittest.TestCase):
    def test_accepts_one_direct_patch_update(self):
        eligible, _ = classify(
            "Updates `github.com/acme/direct` from 1.2.3 to 1.2.4\n",
            DIRECT_GO_MOD,
            ["go.mod", "go.sum"],
        )
        self.assertTrue(eligible)

    def test_rejects_minor_update(self):
        eligible, reason = classify(
            "Updates `github.com/acme/direct` from 1.2.3 to 1.3.0\n",
            DIRECT_GO_MOD,
            ["go.mod", "go.sum"],
        )
        self.assertFalse(eligible)
        self.assertIn("patch", reason)

    def test_rejects_unrelated_files(self):
        eligible, reason = classify(
            "Updates `github.com/acme/direct` from 1.2.3 to 1.2.4\n",
            DIRECT_GO_MOD,
            [".github/workflows/ci.yml", "go.mod", "go.sum"],
        )
        self.assertFalse(eligible)
        self.assertIn("changed files", reason)

    def test_rejects_indirect_dependency(self):
        eligible, reason = classify(
            "Updates `github.com/acme/indirect` from 1.2.3 to 1.2.4\n",
            DIRECT_GO_MOD,
            ["go.mod", "go.sum"],
        )
        self.assertFalse(eligible)
        self.assertIn("direct", reason)
