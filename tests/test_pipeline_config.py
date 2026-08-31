#!/usr/bin/env python3

import importlib.util
import json
import tempfile
import unittest
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
