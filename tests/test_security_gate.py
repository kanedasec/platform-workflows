#!/usr/bin/env python3

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "actions"
    / "sgp-policy-gate"
    / "security_gate.py"
)
SPEC = importlib.util.spec_from_file_location("security_gate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
security_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(security_gate)


class SecurityGateTests(unittest.TestCase):
    def test_semgrep_severities_are_normalized(self):
        report = {
            "results": [
                {"extra": {"severity": "INFO"}},
                {"extra": {"severity": "WARNING"}},
                {"extra": {"severity": "ERROR"}},
                {"extra": {"severity": "CRITICAL"}},
            ]
        }
        self.assertEqual(
            security_gate.semgrep_findings(report),
            ["low", "medium", "high", "critical"],
        )

    def test_unknown_scanner_severity_fails_closed(self):
        semgrep = {"results": [{"extra": {"severity": "UNKNOWN"}}]}
        trivy = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-TEST", "Severity": "UNKNOWN"}
                    ]
                }
            ]
        }
        self.assertEqual(security_gate.semgrep_findings(semgrep), ["critical"])
        self.assertEqual(security_gate.trivy_findings(trivy), ["critical"])

    def test_gitleaks_findings_are_critical(self):
        self.assertEqual(
            security_gate.gitleaks_findings([{"RuleID": "example"}]),
            ["critical"],
        )

    def test_policy_must_match_requested_application_and_gate(self):
        policy = {
            "application": "sgp-manager",
            "generated_at": datetime.now(UTC).isoformat(),
            "gates": [
                {"gate": "sca", "blocking_severities": ["high", "critical"]}
            ],
        }
        blocking, _ = security_gate.validate_policy(policy, "sgp-manager", "sca")
        self.assertEqual(blocking, ["high", "critical"])

        with self.assertRaises(security_gate.GateError):
            security_gate.validate_policy(policy, "different-app", "sca")
        with self.assertRaises(security_gate.GateError):
            security_gate.validate_policy(policy, "sgp-manager", "sast")

    def test_stale_policy_is_rejected(self):
        policy = {
            "application": "sgp-manager",
            "generated_at": (datetime.now(UTC) - timedelta(minutes=10)).isoformat(),
            "gates": [{"gate": "sast", "blocking_severities": ["high"]}],
        }
        with self.assertRaises(security_gate.GateError):
            security_gate.validate_policy(policy, "sgp-manager", "sast")

    def test_unavailable_manager_enforces_every_severity(self):
        with mock.patch.object(
            security_gate,
            "fetch_policy",
            side_effect=security_gate.GateError("manager unavailable"),
        ):
            blocking, generated_at, source = security_gate.resolve_blocking_policy(
                "https://sgp.kanedasec.com.br",
                "configured-key",
                "second-brain",
                "sast",
                1,
            )
        self.assertEqual(blocking, ["low", "medium", "high", "critical"])
        self.assertIsNone(generated_at)
        self.assertEqual(source, "offline-no-bypass")

    def test_missing_manager_credential_enforces_every_severity(self):
        with mock.patch.object(security_gate, "fetch_policy") as fetch:
            blocking, _, source = security_gate.resolve_blocking_policy(
                "https://sgp.kanedasec.com.br", "", "second-brain", "secrets", 1
            )
        fetch.assert_not_called()
        self.assertEqual(blocking, list(security_gate.CANONICAL_SEVERITIES))
        self.assertEqual(source, "offline-no-bypass")

    def test_offline_cli_passes_clean_report_and_blocks_low_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "semgrep.json"
            decision = root / "decision.json"
            arguments = [
                "security_gate.py",
                "--manager-url",
                "https://sgp.kanedasec.com.br",
                "--application",
                "second-brain",
                "--gate",
                "sast",
                "--scanner",
                "semgrep",
                "--report",
                str(report),
                "--decision-output",
                str(decision),
            ]

            report.write_text('{"results": []}', encoding="utf-8")
            with mock.patch.object(sys, "argv", arguments), mock.patch.dict(
                os.environ, {}, clear=True
            ):
                self.assertEqual(security_gate.main(), 0)
            clean = json.loads(decision.read_text(encoding="utf-8"))
            self.assertEqual(clean["decision"], "PASS")
            self.assertEqual(clean["policy_source"], "offline-no-bypass")

            report.write_text(
                '{"results": [{"extra": {"severity": "INFO"}}]}',
                encoding="utf-8",
            )
            with mock.patch.object(sys, "argv", arguments), mock.patch.dict(
                os.environ, {}, clear=True
            ):
                self.assertEqual(security_gate.main(), 1)
            blocked = json.loads(decision.read_text(encoding="utf-8"))
            self.assertEqual(blocked["blocking_findings"], 1)
            self.assertEqual(blocked["decision"], "BLOCK")

    def test_manager_url_must_be_https_without_embedded_credentials(self):
        expected = "https://sgp.kanedasec.com.br/api/v1/policies/evaluate-enforcement"
        self.assertEqual(
            security_gate.enforcement_url("https://sgp.kanedasec.com.br"), expected
        )

        invalid_urls = (
            "http://sgp.kanedasec.com.br",
            "https://user:password@sgp.kanedasec.com.br",
            "https://sgp.kanedasec.com.br?debug=true",
        )
        for url in invalid_urls:
            with self.subTest(url=url), self.assertRaises(security_gate.GateError):
                security_gate.enforcement_url(url)


if __name__ == "__main__":
    unittest.main()
