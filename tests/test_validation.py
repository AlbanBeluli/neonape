import pytest

from neon_ape.services.validation import validate_domain, validate_target, validate_url_or_target


def test_validate_target_accepts_ip_hostname_and_cidr() -> None:
    assert validate_target("127.0.0.1") == "127.0.0.1"
    assert validate_target("example.com") == "example.com"
    assert validate_target("10.0.0.0/24") == "10.0.0.0/24"


def test_validate_target_rejects_invalid_values() -> None:
    with pytest.raises(ValueError):
        validate_target("")
    with pytest.raises(ValueError):
        validate_target("bad target!")


def test_validate_domain_normalizes() -> None:
    assert validate_domain("Example.COM.") == "example.com"


def test_validate_url_or_target_accepts_url_and_falls_back() -> None:
    assert validate_url_or_target("https://example.com") == "https://example.com"
    assert validate_url_or_target("example.com") == "example.com"
