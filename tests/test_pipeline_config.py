#!/usr/bin/env python3

import importlib.util
import json
import tempfile
import unittest
from unittest import mock
from datetime import UTC, datetime, timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pipeline_config = load_module(
    "pipeline_config",
    ROOT / "actions" / "sgp-pipeline-config" / "pipeline_config.py",
)
selected_gates = load_module(
    "selected_gates",
    ROOT / "actions" / "sgp-policy-gate" / "selected_gates.py",
)


def response(gates=None, **changes):
    value = {
        "application": "sgp-manager",
        "generated_at": datetime.now(UTC).isoformat(),
        "gates": gates
        if gates is not None
        else [
            {"gate": "sast", "position": 0},
            {"gate": "secrets", "position": 1},
            {"gate": "sca", "position": 2},
        ],
    }
    value.update(changes)
    return value


class PipelineConfigTests(unittest.TestCase):
    def test_valid_pipeline_preserves_configured_order(self):
        gates = pipeline_config.validate_pipeline(
            response(
                [
                    {"gate": "secrets", "position": 0},
                    {"gate": "sast", "position": 1},
                ]
            ),
            "sgp-manager",
        )
        self.assertEqual(gates, ["secrets", "sast"])

    def test_invalid_pipeline_contracts_fail_closed(self):
        invalid = (
            response([]),
            response([{"gate": "dast", "position": 0}]),
            response(
                [
                    {"gate": "sast", "position": 0},
                    {"gate": "sast", "position": 1},
                ]
            ),
            response(
                [
                    {"gate": "sast", "position": 0},
                    {"gate": "sca", "position": 2},
                ]
            ),
            response([{"gate": "sast", "position": True}]),
            response(application="different-application"),
            response(generated_at=(datetime.now(UTC) - timedelta(minutes=10)).isoformat()),
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(
                pipeline_config.PipelineConfigError
            ):
                pipeline_config.validate_pipeline(value, "sgp-manager")

    def test_manager_url_is_fixed_to_https_without_embedded_credentials(self):
        self.assertEqual(
            pipeline_config.resolution_url("https://sgp.kanedasec.com.br"),
            "https://sgp.kanedasec.com.br/api/v1/policies/resolve-pipeline",
        )
        for url in (
            "http://sgp.kanedasec.com.br",
            "https://user:password@sgp.kanedasec.com.br",
            "https://sgp.kanedasec.com.br?debug=true",
        ):
            with self.subTest(url=url), self.assertRaises(
                pipeline_config.PipelineConfigError
            ):
                pipeline_config.resolution_url(url)

    def test_validated_response_is_written_without_credentials(self):
        value = response()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "pipeline.json"
            pipeline_config.write_response(output, value)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), value)

    def test_unavailable_manager_selects_every_gate_without_bypasses(self):
        with mock.patch.object(
            pipeline_config,
            "fetch_pipeline",
            side_effect=pipeline_config.PipelineConfigError("manager unavailable"),
        ):
            result, gates, fallback_active = pipeline_config.resolve_pipeline_or_fallback(
                "https://sgp.kanedasec.com.br",
                "configured-key",
                "second-brain",
                1,
            )

        self.assertTrue(fallback_active)
        self.assertEqual(gates, ["sast", "secrets", "sca"])
        self.assertEqual(result["policy_mode"], "offline-no-bypass")
        self.assertEqual(result["execution_gates"], ["sast", "secrets", "sca"])
        self.assertEqual(
            result["gates"],
            [
                {"gate": "sast", "position": 0},
                {"gate": "secrets", "position": 1},
                {"gate": "sca", "position": 2},
            ],
        )

    def test_missing_manager_credential_also_uses_strict_fallback(self):
        with mock.patch.object(pipeline_config, "fetch_pipeline") as fetch:
            _, gates, fallback_active = pipeline_config.resolve_pipeline_or_fallback(
                "https://sgp.kanedasec.com.br", "", "second-brain", 1
            )
        fetch.assert_not_called()
        self.assertTrue(fallback_active)
        self.assertEqual(gates, list(pipeline_config.KNOWN_GATES))

    def test_online_configuration_cannot_omit_scanner_execution(self):
        configured = response([{"gate": "secrets", "position": 0}])
        with mock.patch.object(
            pipeline_config, "fetch_pipeline", return_value=configured
        ):
            result, gates, fallback_active = pipeline_config.resolve_pipeline_or_fallback(
                "https://sgp.kanedasec.com.br",
                "configured-key",
                "sgp-manager",
                1,
            )
        self.assertFalse(fallback_active)
        self.assertEqual(gates, ["secrets", "sast", "sca"])
        self.assertEqual(result["execution_gates"], gates)
        self.assertEqual(result["policy_mode"], "sgp-bypass-aware")

    def test_invalid_application_never_enters_fallback(self):
        with self.assertRaises(pipeline_config.PipelineConfigError):
            pipeline_config.resolve_pipeline_or_fallback(
                "https://sgp.kanedasec.com.br", "", "INVALID APP", 1
            )

    def test_selected_gate_input_is_strict(self):
        self.assertEqual(
            selected_gates.validate_selected_gates('["sca","sast"]'),
            ["sca", "sast"],
        )
        for value in (
            "not-json",
            "[]",
            '["sast","sast"]',
            '["dast"]',
            '{"gate":"sast"}',
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                selected_gates.validate_selected_gates(value)


if __name__ == "__main__":
    unittest.main()
