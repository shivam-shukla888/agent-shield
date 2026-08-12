"""
Unit tests for SSRF Security Boundary (STEP 10C).
"""

import pytest

from app.domain.target import TargetErrorCode
from app.security.ssrf import SSRFPolicy, SSRFValidator


def mock_public_dns_resolver(hostname: str):
    return ["93.184.216.34"]


def mock_private_dns_resolver(hostname: str):
    return ["10.0.0.5"]


def mock_loopback_dns_resolver(hostname: str):
    return ["127.0.0.1"]


def mock_failing_dns_resolver(hostname: str):
    raise ValueError("DNS lookup failed")


def test_http_url_accepted_structurally():
    validator = SSRFValidator(dns_resolver=mock_public_dns_resolver)
    is_safe, reason = validator.validate_url("http://example.com/api")
    assert is_safe is True


def test_https_url_accepted_structurally():
    validator = SSRFValidator(dns_resolver=mock_public_dns_resolver)
    is_safe, reason = validator.validate_url("https://example.com/api")
    assert is_safe is True


def test_file_scheme_rejected():
    validator = SSRFValidator(dns_resolver=mock_public_dns_resolver)
    is_safe, reason = validator.validate_url("file:///etc/passwd")
    assert is_safe is False
    assert "scheme 'file' is not permitted" in reason


def test_ftp_scheme_rejected():
    validator = SSRFValidator(dns_resolver=mock_public_dns_resolver)
    is_safe, reason = validator.validate_url("ftp://example.com/file")
    assert is_safe is False
    assert "scheme 'ftp' is not permitted" in reason


def test_localhost_rejected():
    validator = SSRFValidator()
    is_safe, reason = validator.validate_url("http://localhost/chat")
    assert is_safe is False
    assert "blocked by SSRF policy" in reason


def test_localhost_localdomain_rejected():
    validator = SSRFValidator()
    is_safe, reason = validator.validate_url("http://localhost.localdomain/chat")
    assert is_safe is False
    assert "blocked by SSRF policy" in reason


def test_127_0_0_1_rejected():
    validator = SSRFValidator()
    is_safe, reason = validator.validate_url("http://127.0.0.1:8000/chat")
    assert is_safe is False
    assert "Loopback IP address is blocked" in reason


def test_127_x_x_x_rejected():
    validator = SSRFValidator()
    is_safe, reason = validator.validate_url("http://127.0.1.55:8000/chat")
    assert is_safe is False
    assert "Loopback IP address is blocked" in reason


def test_ipv6_loopback_rejected():
    validator = SSRFValidator()
    is_safe, reason = validator.validate_url("http://[::1]:8000/chat")
    assert is_safe is False
    assert "Loopback IP address is blocked" in reason


def test_10_0_0_0_8_rejected():
    validator = SSRFValidator()
    is_safe, reason = validator.validate_url("http://10.0.1.15/chat")
    assert is_safe is False
    assert "Private RFC1918" in reason


def test_172_16_0_0_12_rejected():
    validator = SSRFValidator()
    is_safe, reason = validator.validate_url("http://172.20.5.1/chat")
    assert is_safe is False
    assert "Private RFC1918" in reason


def test_192_168_0_0_16_rejected():
    validator = SSRFValidator()
    is_safe, reason = validator.validate_url("http://192.168.1.100/chat")
    assert is_safe is False
    assert "Private RFC1918" in reason


def test_169_254_0_0_16_rejected():
    validator = SSRFValidator()
    is_safe, reason = validator.validate_url("http://169.254.5.5/chat")
    assert is_safe is False
    assert "Link-local IP address is blocked" in reason


def test_169_254_169_254_cloud_metadata_rejected():
    validator = SSRFValidator()
    is_safe, reason = validator.validate_url("http://169.254.169.254/latest/meta-data")
    assert is_safe is False
    assert "Cloud metadata IP" in reason or "Link-local" in reason


def test_ipv6_unique_local_rejected():
    validator = SSRFValidator()
    is_safe, reason = validator.validate_url("http://[fc00::1]/chat")
    assert is_safe is False
    assert "Private RFC1918 / unique-local" in reason


def test_ipv6_link_local_rejected():
    validator = SSRFValidator()
    is_safe, reason = validator.validate_url("http://[fe80::1]/chat")
    assert is_safe is False
    assert "Link-local IP address is blocked" in reason


def test_unspecified_address_rejected():
    validator = SSRFValidator()
    is_safe, reason = validator.validate_url("http://0.0.0.0/chat")
    assert is_safe is False
    assert "Unspecified IP address is blocked" in reason


def test_multicast_address_rejected():
    validator = SSRFValidator()
    is_safe, reason = validator.validate_url("http://224.0.0.1/chat")
    assert is_safe is False
    assert "Multicast IP address is blocked" in reason


def test_reserved_special_ip_rejected():
    validator = SSRFValidator()
    is_safe, reason = validator.validate_url("http://240.0.0.1/chat")
    assert is_safe is False
    assert "Reserved" in reason or "special-use" in reason


def test_hostname_resolving_to_public_ip_accepted():
    validator = SSRFValidator(dns_resolver=mock_public_dns_resolver)
    is_safe, reason = validator.validate_url("http://public-target.com/chat")
    assert is_safe is True


def test_hostname_resolving_to_private_ip_rejected():
    validator = SSRFValidator(dns_resolver=mock_private_dns_resolver)
    is_safe, reason = validator.validate_url("http://attacker-controlled.example/chat")
    assert is_safe is False
    assert "Destination IP address is blocked" in reason


def test_hostname_resolving_to_loopback_rejected():
    validator = SSRFValidator(dns_resolver=mock_loopback_dns_resolver)
    is_safe, reason = validator.validate_url("http://dns-rebind.example/chat")
    assert is_safe is False
    assert "Destination IP address is blocked" in reason


def test_dns_resolution_failure_safely_rejected():
    validator = SSRFValidator(dns_resolver=mock_failing_dns_resolver)
    is_safe, reason = validator.validate_url("http://nonexistent.domain.fail/chat")
    assert is_safe is False
    assert "DNS resolution failure" in reason


def test_malformed_hostname_rejected():
    validator = SSRFValidator()
    is_safe, reason = validator.validate_url("http://")
    assert is_safe is False


def test_empty_hostname_rejected():
    validator = SSRFValidator()
    is_safe, reason = validator.validate_url("http:// /chat")
    assert is_safe is False


def test_explicit_port_handled_correctly():
    validator = SSRFValidator(dns_resolver=mock_public_dns_resolver)
    is_safe, reason = validator.validate_url("http://public-target.com:8443/chat")
    assert is_safe is True


def test_ipv6_literal_parsing_handled():
    validator = SSRFValidator()
    is_safe, reason = validator.validate_url("http://[2606:4700:4700::1111]:8080/chat")
    assert is_safe is True


def test_userinfo_does_not_leak_into_errors():
    validator = SSRFValidator(dns_resolver=mock_private_dns_resolver)
    is_safe, reason = validator.validate_url("http://admin:SECRET_PASSWORD@private.internal/chat")
    assert is_safe is False
    assert "SECRET_PASSWORD" not in reason
    assert "admin" not in reason


def test_ssrf_rejection_maps_to_ssrf_rejection_code():
    assert TargetErrorCode.SSRF_REJECTION == "ssrf_rejection"


def test_ssrf_rejection_does_not_expose_credentials():
    validator = SSRFValidator()
    is_safe, reason = validator.validate_url("http://bearer_token_val@127.0.0.1/chat")
    assert "bearer_token_val" not in reason
