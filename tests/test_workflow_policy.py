#!/usr/bin/env python3

import re
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_FILES = tuple(sorted((ROOT / ".github" / "workflows").glob("*.yaml")))
ACTION_FILES = tuple(sorted((ROOT / "actions").glob("*/action.yml")))
USES_PATTERN = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)
FULL_SHA_REFERENCE = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")


class WorkflowPolicyTests(unittest.TestCase):
    def test_composite_action_metadata_is_valid_yaml(self):
        for path in ACTION_FILES:
            with self.subTest(path=path):
                document = yaml.safe_load(path.read_text(encoding="utf-8"))
                self.assertIsInstance(document, dict)
                self.assertIsInstance(document.get("runs", {}).get("steps"), list)

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

    def test_security_scanners_require_selected_gate_input(self):
        workflow = (
            ROOT / ".github" / "workflows" / "security-differential.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("gates:\n        description:", workflow)
        self.assertIn("required: true\n        type: string", workflow)
        for gate in ("sast", "secrets", "sca"):
            self.assertIn(
                f"if: contains(fromJSON(inputs.gates), '{gate}')", workflow
            )

    def test_policy_wrapper_downloads_only_selected_artifacts(self):
        action = (
            ROOT / "actions" / "sgp-policy-from-artifacts" / "action.yml"
        ).read_text(encoding="utf-8")
        self.assertEqual(action.count("if: contains(fromJSON(inputs.gates)"), 3)
        self.assertIn("gates: ${{ inputs.gates }}", action)
        self.assertIn(
            "sgp-policy-gate@a37957650934407003aed3b9e8ce4caba1427dd3",
            action,
        )


if __name__ == "__main__":
    unittest.main()
