#!/usr/bin/env python3

import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "actions"
    / "trivy-diff"
    / "trivy_diff.py"
)
SPEC = importlib.util.spec_from_file_location("trivy_diff", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
trivy_diff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trivy_diff)


class TrivyDiffTests(unittest.TestCase):
    def test_only_new_vulnerability_is_emitted(self):
        existing = {
            "VulnerabilityID": "CVE-OLD",
            "PkgName": "old-package",
            "InstalledVersion": "1.0",
            "Severity": "HIGH",
        }
        introduced = {
            "VulnerabilityID": "CVE-NEW",
            "PkgName": "new-package",
            "InstalledVersion": "2.0",
            "Severity": "CRITICAL",
        }
        base = {
            "Results": [
                {
                    "Target": "frontend/package-lock.json",
                    "Class": "lang-pkgs",
                    "Type": "npm",
                    "Vulnerabilities": [existing],
                }
            ]
        }
        head = {
            "Results": [
                {
                    "Target": "./frontend/package-lock.json",
                    "Class": "lang-pkgs",
                    "Type": "npm",
                    "Vulnerabilities": [existing, introduced],
                }
            ]
        }

        delta, findings = trivy_diff.build_delta(base, head)

        self.assertEqual(findings, [introduced])
        self.assertEqual(delta["Results"][0]["Vulnerabilities"], [introduced])

    def test_same_cve_in_another_package_is_new(self):
        base = {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Class": "lang-pkgs",
                    "Type": "pip",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-SHARED",
                            "PkgName": "package-a",
                            "InstalledVersion": "1.0",
                        }
                    ],
                }
            ]
        }
        introduced = {
            "VulnerabilityID": "CVE-SHARED",
            "PkgName": "package-b",
            "InstalledVersion": "1.0",
        }
        head = {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Class": "lang-pkgs",
                    "Type": "pip",
                    "Vulnerabilities": [introduced],
                }
            ]
        }

        _, findings = trivy_diff.build_delta(base, head)
        self.assertEqual(findings, [introduced])


if __name__ == "__main__":
    unittest.main()
