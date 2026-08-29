#!/usr/bin/env python3

import ipaddress
import os
import re
from urllib.parse import urlsplit


TAILSCALE_IPV4_RANGE = ipaddress.ip_network("100.64.0.0/10")
TARGET_USER_PATTERN = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
DEPLOY_COMMAND_PATTERN = re.compile(r"[a-z][a-z0-9-]{0,63}")
IMAGE_TAG_PATTERN = re.compile(r"sha-[0-9a-f]{40}")
READINESS_PATH_PATTERN = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*")


def validate_target_host(value: str) -> None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError("target_host must be a Tailscale IPv4 address") from error

    if address.version != 4 or address not in TAILSCALE_IPV4_RANGE:
        raise ValueError("target_host must be inside 100.64.0.0/10")


def validate_target_user(value: str) -> None:
    if not TARGET_USER_PATTERN.fullmatch(value):
        raise ValueError("target_user is not a valid restricted Unix account")


def validate_deploy_command(value: str) -> None:
    if not DEPLOY_COMMAND_PATTERN.fullmatch(value):
        raise ValueError("deploy_command must be a command name without arguments")


def validate_image_tag(value: str) -> None:
    if not IMAGE_TAG_PATTERN.fullmatch(value):
        raise ValueError("image_tag must be sha- followed by 40 lowercase hex characters")


def validate_public_url(value: str) -> None:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("public_url must not contain control characters")

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("public_url is invalid") from error

    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("public_url must be an HTTPS origin without credentials or a path")


def validate_readiness_path(value: str) -> None:
    if (
        not READINESS_PATH_PATTERN.fullmatch(value)
        or "//" in value
        or ".." in value.split("/")
    ):
        raise ValueError("readiness_path must be a safe absolute URL path")


def validate_environment(environment: dict[str, str]) -> None:
    required = (
        "TARGET_HOST",
        "TARGET_USER",
        "DEPLOY_COMMAND",
        "IMAGE_TAG",
        "PUBLIC_URL",
        "READINESS_PATH",
    )
    missing = [name for name in required if not environment.get(name)]
    if missing:
        raise ValueError("missing deployment input(s): " + ", ".join(missing))

    validate_target_host(environment["TARGET_HOST"])
    validate_target_user(environment["TARGET_USER"])
    validate_deploy_command(environment["DEPLOY_COMMAND"])
    validate_image_tag(environment["IMAGE_TAG"])
    validate_public_url(environment["PUBLIC_URL"])
    validate_readiness_path(environment["READINESS_PATH"])


def main() -> None:
    try:
        validate_environment(dict(os.environ))
    except ValueError as error:
        raise SystemExit(f"invalid deployment configuration: {error}") from error


if __name__ == "__main__":
    main()
