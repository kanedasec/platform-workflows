#!/usr/bin/env python3
"""Validate a selected-gate JSON array for the policy action."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


KNOWN_GATES = ("sast", "secrets", "sca")


def validate_selected_gates(raw_value: str) -> list[str]:
    try:
        value = json.loads(raw_value)
    except json.JSONDecodeError as error:
        raise ValueError("selected gates must be valid JSON") from error
    if not isinstance(value, list) or not value:
        raise ValueError("selected gates must be a non-empty JSON array")
    if not all(isinstance(gate, str) and gate in KNOWN_GATES for gate in value):
        raise ValueError("selected gates contain an unsupported gate")
    if len(set(value)) != len(value):
        raise ValueError("selected gates contain duplicates")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gates", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        gates = validate_selected_gates(args.gates)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text("".join(f"{gate}\n" for gate in gates), encoding="utf-8")
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
