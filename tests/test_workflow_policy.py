#!/usr/bin/env python3

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_FILES = tuple(sorted((ROOT / ".github" / "workflows").glob("*.yaml")))
ACTION_FILES = tuple(sorted((ROOT / "actions").glob("*/action.yml")))
USES_PATTERN = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)
FULL_SHA_REFERENCE = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")


class WorkflowPolicyTests(unittest.TestCase):
    def test_external_actions_and_workflows_use_full_commit_shas(self):
        for path in WORKFLOW_FILES + ACTION_FILES:
            contents = path.read_text(encoding="utf-8")
            for reference in USES_PATTERN.findall(contents):
                if reference.startswith("./"):
                    continue
                with self.subTest(path=path, reference=reference):
                    self.assertRegex(reference, FULL_SHA_REFERENCE)

    def test_pull_request_target_is_not_used(self):
        for path in WORKFLOW_FILES:
            with self.subTest(path=path):
                self.assertNotIn(
                    "pull_request_target:", path.read_text(encoding="utf-8")
                )

    def test_checkout_credentials_are_not_persisted(self):
        for path in WORKFLOW_FILES:
            contents = path.read_text(encoding="utf-8")
            checkout_count = contents.count("uses: actions/checkout@")
            disabled_count = contents.count("persist-credentials: false")
            with self.subTest(path=path):
                self.assertEqual(checkout_count, disabled_count)

    def test_pipeline_resolver_has_no_caller_controlled_destination(self):
        action = (
            ROOT / "actions" / "sgp-pipeline-config" / "action.yml"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "actions" / "sgp-pipeline-config" / "pipeline_config.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("inputs:", action)
        self.assertIn("https://sgp.kanedasec.com.br", action)
        self.assertIn("github.event.repository.name", action)
        self.assertIn("class RejectRedirects", implementation)

    def test_policy_gate_default_remains_backward_compatible(self):
        action = (
            ROOT / "actions" / "sgp-policy-gate" / "action.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("default: '[\"sast\",\"secrets\",\"sca\"]'", action)


if __name__ == "__main__":
    unittest.main()
