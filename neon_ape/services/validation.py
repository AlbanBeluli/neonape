from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


HOSTNAME_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def validate_target(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Target cannot be empty")

    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        pass

    if HOSTNAME_RE.fullmatch(value):
        return value

    raise ValueError(f"Invalid target: {value}")


def validate_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if not value or not HOSTNAME_RE.fullmatch(value) or "." not in value:
        raise ValueError(f"Invalid domain: {value}")
    return value


def validate_url_or_target(value: str) -> str:
    value = value.strip()
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return value
    return validate_target(value)
