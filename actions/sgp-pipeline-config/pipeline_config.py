#!/usr/bin/env python3
"""Resolve and strictly validate the SGP Manager security pipeline."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


KNOWN_GATES = ("sast", "secrets", "sca")
APPLICATION_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class PipelineConfigError(ValueError):
    """An operational or validation error that must stop the workflow."""


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Keep the API credential bound to the configured SGP Manager origin."""

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Resolve the SGP security pipeline")
    parser.add_argument("--manager-url", required=True)
    parser.add_argument("--application", required=True)
    parser.add_argument("--response-output", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=10.0)
    return parser.parse_args()


def resolution_url(manager_url: str) -> str:
    parsed = urllib.parse.urlsplit(manager_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise PipelineConfigError("SGP Manager URL must be an absolute HTTPS URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise PipelineConfigError(
            "SGP Manager URL must not contain credentials, a query, or a fragment"
        )
    return urllib.parse.urljoin(
        manager_url.rstrip("/") + "/", "api/v1/policies/resolve-pipeline"
    )


def fetch_pipeline(
    manager_url: str, api_key: str, application: str, timeout: float
) -> dict[str, Any]:
    request = urllib.request.Request(
        resolution_url(manager_url),
        data=json.dumps({"application": application}).encode(),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
            "User-Agent": "sgp-manager-ci-pipeline-resolver/1",
        },
    )
    opener = urllib.request.build_opener(RejectRedirects)
    try:
        with opener.open(request, timeout=timeout) as response:
            response_body = response.read(65_537)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as error:
        raise PipelineConfigError(f"SGP Manager pipeline request failed: {error}") from error

    if len(response_body) > 65_536:
        raise PipelineConfigError("SGP Manager pipeline response is too large")
    try:
        result = json.loads(response_body)
    except json.JSONDecodeError as error:
        raise PipelineConfigError("SGP Manager returned invalid JSON") from error
    if not isinstance(result, dict):
        raise PipelineConfigError("SGP Manager returned an invalid pipeline object")
    return result


def validate_generated_at(value: Any) -> str:
    if not isinstance(value, str):
        raise PipelineConfigError("SGP Manager response has no generated_at timestamp")
    try:
        generated_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise PipelineConfigError("SGP Manager returned an invalid generated_at timestamp") from error
    if generated_at.tzinfo is None:
        raise PipelineConfigError("SGP Manager generated_at timestamp has no timezone")
    age = (datetime.now(UTC) - generated_at.astimezone(UTC)).total_seconds()
    if age < -60 or age > 300:
        raise PipelineConfigError("SGP Manager returned a stale or future pipeline response")
    return value


def validate_pipeline(result: dict[str, Any], application: str) -> list[str]:
    if not APPLICATION_PATTERN.fullmatch(application) or len(application) > 100:
        raise PipelineConfigError("invalid application slug")
    if result.get("application") != application:
        raise PipelineConfigError("SGP Manager returned a different application")
    validate_generated_at(result.get("generated_at"))

    entries = result.get("gates")
    if not isinstance(entries, list) or not entries:
        raise PipelineConfigError("SGP Manager returned an empty or invalid security pipeline")
    if len(entries) > len(KNOWN_GATES):
        raise PipelineConfigError("SGP Manager returned too many security gates")

    gates: list[str] = []
    positions: list[int] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise PipelineConfigError("SGP Manager returned an invalid pipeline gate")
        gate = entry.get("gate")
        position = entry.get("position")
        if not isinstance(gate, str) or gate not in KNOWN_GATES:
            raise PipelineConfigError(f"SGP Manager returned unsupported gate: {gate!r}")
        if isinstance(position, bool) or not isinstance(position, int):
            raise PipelineConfigError("SGP Manager returned an invalid gate position")
        gates.append(gate)
        positions.append(position)

    if len(set(gates)) != len(gates):
        raise PipelineConfigError("SGP Manager returned duplicate security gates")
    if positions != list(range(len(entries))):
        raise PipelineConfigError("SGP Manager returned non-contiguous gate positions")
    return gates


def write_response(path: Path, result: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("w", encoding="utf-8") as output_file:
            json.dump(result, output_file, indent=2)
            output_file.write("\n")
    except OSError as error:
        raise PipelineConfigError(f"cannot write pipeline configuration {path}: {error}") from error


def main() -> int:
    args = parse_args()
    api_key = os.environ.get("SGP_MANAGER_API_KEY", "")
    if not api_key or len(api_key) > 256:
        print("error: SGP_MANAGER_API_KEY is missing or invalid", file=sys.stderr)
        return 2
    try:
        result = fetch_pipeline(
            args.manager_url, api_key, args.application, args.timeout
        )
        gates = validate_pipeline(result, args.application)
        write_response(args.response_output, result)
    except PipelineConfigError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(json.dumps(gates, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
