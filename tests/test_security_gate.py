#!/usr/bin/env python3

import importlib.util
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path


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
