#!/usr/bin/env python3

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = (
    ROOT / "actions" / "tailscale-ssh-deploy" / "validate_inputs.py"
)
SPEC = importlib.util.spec_from_file_location("deploy_input_validation", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
VALIDATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATION)


class DeploymentInputValidationTests(unittest.TestCase):
    def setUp(self):
        self.configuration = {
            "TARGET_HOST": "100.114.123.6",
            "TARGET_USER": "deployer",
            "DEPLOY_COMMAND": "deploy-sgp-manager",
            "IMAGE_TAG": "sha-" + "a" * 40,
            "PUBLIC_URL": "https://sgp.kanedasec.com.br",
            "ROOT_EXPECTED_STATUS": "200",
            "READINESS_PATH": "/ready",
        }

    def test_valid_configuration(self):
        VALIDATION.validate_environment(self.configuration)

    def test_target_must_be_a_tailscale_ipv4_address(self):
        for value in ("152.53.48.159", "fd7a:115c:a1e0::1", "example.com"):
            with self.subTest(value=value):
                configuration = self.configuration | {"TARGET_HOST": value}
                with self.assertRaises(ValueError):
                    VALIDATION.validate_environment(configuration)

    def test_target_user_rejects_shell_syntax(self):
        configuration = self.configuration | {"TARGET_USER": "deployer;id"}
        with self.assertRaises(ValueError):
            VALIDATION.validate_environment(configuration)

    def test_deploy_command_rejects_arguments(self):
        configuration = self.configuration | {
            "DEPLOY_COMMAND": "deploy-sgp-manager --unsafe"
        }
        with self.assertRaises(ValueError):
            VALIDATION.validate_environment(configuration)

    def test_image_tag_requires_a_full_lowercase_commit_sha(self):
        for value in ("dev", "latest", "sha-deadbeef", "sha-" + "A" * 40):
            with self.subTest(value=value):
                configuration = self.configuration | {"IMAGE_TAG": value}
                with self.assertRaises(ValueError):
                    VALIDATION.validate_environment(configuration)

    def test_public_url_requires_a_clean_https_origin(self):
        invalid_values = (
            "http://sgp.kanedasec.com.br",
            "https://user@example.com",
            "https://sgp.kanedasec.com.br/path",
            "https://sgp.kanedasec.com.br?query=true",
            "https://sgp.kanedasec.com.br:8443",
            "https://sgp.kanedasec.com.br\n.example.com",
        )
        for value in invalid_values:
            with self.subTest(value=value):
                configuration = self.configuration | {"PUBLIC_URL": value}
                with self.assertRaises(ValueError):
                    VALIDATION.validate_environment(configuration)

    def test_readiness_path_rejects_traversal_and_urls(self):
        for value in ("ready", "//example.com/ready", "/../ready", "/ready?x=1"):
            with self.subTest(value=value):
                configuration = self.configuration | {"READINESS_PATH": value}
                with self.assertRaises(ValueError):
                    VALIDATION.validate_environment(configuration)

    def test_authenticated_root_status_is_accepted(self):
        configuration = self.configuration | {"ROOT_EXPECTED_STATUS": "401"}
        VALIDATION.validate_environment(configuration)

    def test_root_status_rejects_errors_and_invalid_values(self):
        for value in ("", "199", "400", "404", "500", "two-hundred"):
            with self.subTest(value=value):
                configuration = self.configuration | {
                    "ROOT_EXPECTED_STATUS": value
                }
                with self.assertRaises(ValueError):
                    VALIDATION.validate_environment(configuration)

    def test_missing_input_is_rejected(self):
        del self.configuration["TARGET_HOST"]
        with self.assertRaises(ValueError):
            VALIDATION.validate_environment(self.configuration)


if __name__ == "__main__":
    unittest.main()
