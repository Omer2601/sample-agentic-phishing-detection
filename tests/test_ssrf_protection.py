# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Unit tests for SSRF protection in validate_url() and resolve_and_validate().

Tests cover:
- IMDS (169.254.169.254)
- Loopback (127.0.0.0/8, ::1)
- RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Link-local (169.254.0.0/16)
- ECS metadata (169.254.170.2)
- .internal/.local domains
- Embedded credentials (user:pass@host)
- Non-standard ports (only allow 80/443)
- DNS rebinding (resolve and re-check)
"""

import ipaddress
import unittest
from unittest.mock import patch

import pytest

from phish_agents.common.url_safety import resolve_and_validate, validate_url

# The all-zeros IPv4 address, the unspecified/wildcard address that stands for
# every local interface. Built from ipaddress so it reads as what it means.
ALL_ZEROS_V4 = str(ipaddress.IPv4Address(0))


class TestValidateUrl(unittest.TestCase):
    """Tests for the validate_url() function: static URL validation."""

    # ── Happy path: valid URLs should pass ──

    def test_valid_https_url(self):
        self.assertIsNone(validate_url("https://example.com"))

    def test_valid_http_url(self):
        self.assertIsNone(validate_url("http://example.com"))

    def test_valid_url_with_path(self):
        self.assertIsNone(validate_url("https://example.com/path/to/page"))

    def test_valid_url_with_query(self):
        self.assertIsNone(validate_url("https://example.com/page?q=search&lang=en"))

    def test_valid_url_port_80(self):
        self.assertIsNone(validate_url("http://example.com:80/path"))

    def test_valid_url_port_443(self):
        self.assertIsNone(validate_url("https://example.com:443/path"))

    # ── Scheme validation ──

    def test_rejects_javascript_scheme(self):
        result = validate_url("javascript:alert(1)")
        self.assertIsNotNone(result)
        self.assertIn("http", result)

    def test_rejects_ftp_scheme(self):
        result = validate_url("ftp://example.com/file")
        self.assertIsNotNone(result)

    def test_rejects_file_scheme(self):
        result = validate_url("file:///etc/passwd")
        self.assertIsNotNone(result)

    def test_rejects_data_scheme(self):
        result = validate_url("data:text/html,<h1>hi</h1>")
        self.assertIsNotNone(result)

    # ── Length validation ──

    def test_rejects_url_over_2048_chars(self):
        long_url = "https://example.com/" + "a" * 2030
        result = validate_url(long_url)
        self.assertIsNotNone(result)
        self.assertIn("2048", result)

    # ── Embedded credentials ──

    def test_rejects_username_in_url(self):
        result = validate_url("https://admin@example.com/")
        self.assertIsNotNone(result)
        self.assertIn("credentials", result)

    def test_rejects_user_pass_in_url(self):
        result = validate_url("https://admin:password@example.com/")
        self.assertIsNotNone(result)
        self.assertIn("credentials", result)

    def test_rejects_user_pass_with_special_chars(self):
        result = validate_url("https://user:p%40ss@internal.corp/")
        self.assertIsNotNone(result)
        self.assertIn("credentials", result)

    # ── Port validation ──

    def test_rejects_port_8080(self):
        result = validate_url("https://example.com:8080/path")
        self.assertIsNotNone(result)
        self.assertIn("port", result)

    def test_rejects_port_22(self):
        result = validate_url("https://example.com:22/path")
        self.assertIsNotNone(result)
        self.assertIn("port", result)

    def test_rejects_port_3000(self):
        result = validate_url("http://example.com:3000/api")
        self.assertIsNotNone(result)
        self.assertIn("port", result)

    def test_rejects_port_6379_redis(self):
        result = validate_url("http://example.com:6379/")
        self.assertIsNotNone(result)

    # ── IMDS IP blocking ──

    def test_rejects_imds_ip(self):
        result = validate_url("http://169.254.169.254/latest/meta-data/")
        self.assertIsNotNone(result)
        self.assertIn("blocked", result)

    def test_rejects_imds_with_path(self):
        result = validate_url("http://169.254.169.254/latest/api/token")
        self.assertIsNotNone(result)

    # ── ECS metadata IP blocking ──

    def test_rejects_ecs_metadata(self):
        result = validate_url("http://169.254.170.2/v2/metadata")
        self.assertIsNotNone(result)
        self.assertIn("blocked", result)

    # ── Loopback blocking ──

    def test_rejects_localhost_ip(self):
        result = validate_url("http://127.0.0.1/")
        self.assertIsNotNone(result)
        self.assertIn("blocked", result)

    def test_rejects_127_x_ip(self):
        result = validate_url("http://127.0.0.2/admin")
        self.assertIsNotNone(result)

    def test_rejects_127_255(self):
        result = validate_url("http://127.255.255.255/")
        self.assertIsNotNone(result)

    # ── RFC1918 private ranges ──

    def test_rejects_10_network(self):
        result = validate_url("http://10.0.0.1/internal")
        self.assertIsNotNone(result)
        self.assertIn("blocked", result)

    def test_rejects_10_deep(self):
        result = validate_url("http://10.255.255.255/")
        self.assertIsNotNone(result)

    def test_rejects_172_16_network(self):
        result = validate_url("http://172.16.0.1/")
        self.assertIsNotNone(result)
        self.assertIn("blocked", result)

    def test_rejects_172_31(self):
        result = validate_url("http://172.31.255.255/")
        self.assertIsNotNone(result)

    def test_allows_172_32(self):
        """172.32.0.0 is NOT private (outside /12 range)."""
        self.assertIsNone(validate_url("http://172.32.0.1/"))

    def test_rejects_192_168_network(self):
        result = validate_url("http://192.168.1.1/router")
        self.assertIsNotNone(result)
        self.assertIn("blocked", result)

    def test_rejects_192_168_deep(self):
        result = validate_url("http://192.168.255.255/")
        self.assertIsNotNone(result)

    # ── Link-local blocking ──

    def test_rejects_link_local(self):
        result = validate_url("http://169.254.1.1/")
        self.assertIsNotNone(result)

    def test_rejects_link_local_other(self):
        result = validate_url("http://169.254.255.255/")
        self.assertIsNotNone(result)

    # ── Domain suffix blocking ──

    def test_rejects_internal_domain(self):
        result = validate_url("https://service.internal/api")
        self.assertIsNotNone(result)
        self.assertIn("blocked", result)

    def test_rejects_local_domain(self):
        result = validate_url("https://printer.local/status")
        self.assertIsNotNone(result)
        self.assertIn("blocked", result)

    def test_rejects_localhost_domain(self):
        result = validate_url("https://app.localhost/")
        self.assertIsNotNone(result)
        self.assertIn("blocked", result)

    def test_rejects_corp_domain(self):
        result = validate_url("https://wiki.corp/page")
        self.assertIsNotNone(result)
        self.assertIn("blocked", result)

    def test_rejects_lan_domain(self):
        result = validate_url("https://nas.lan/files")
        self.assertIsNotNone(result)

    def test_rejects_intranet_domain(self):
        result = validate_url("https://portal.intranet/dashboard")
        self.assertIsNotNone(result)

    # ── Edge cases ──

    def test_rejects_empty_string(self):
        result = validate_url("")
        self.assertIsNotNone(result)

    def test_rejects_none(self):
        result = validate_url(None)
        self.assertIsNotNone(result)

    def test_rejects_non_string(self):
        result = validate_url(12345)
        self.assertIsNotNone(result)

    def test_rejects_ipv6_loopback(self):
        result = validate_url("http://[::1]/")
        self.assertIsNotNone(result)
        self.assertIn("blocked", result)


class TestResolveAndValidate(unittest.TestCase):
    """Tests for resolve_and_validate(): DNS resolution SSRF checks."""

    def _mock_getaddrinfo(self, ip_str):
        """Helper to mock socket.getaddrinfo returning a specific IP."""
        return [(2, 1, 6, "", (ip_str, 0))]

    @patch("socket.getaddrinfo")
    def test_allows_public_ip(self, mock_dns):
        mock_dns.return_value = self._mock_getaddrinfo("93.184.216.34")  # example.com
        self.assertIsNone(resolve_and_validate("https://example.com"))

    @patch("socket.getaddrinfo")
    def test_blocks_dns_rebinding_to_imds(self, mock_dns):
        """Domain resolves to IMDS IP: classic DNS rebinding attack."""
        mock_dns.return_value = self._mock_getaddrinfo("169.254.169.254")
        result = resolve_and_validate("https://evil-rebind.attacker.com/")
        self.assertIsNotNone(result)
        self.assertIn("169.254.169.254", result)
        self.assertIn("rebinding", result)

    @patch("socket.getaddrinfo")
    def test_blocks_dns_rebinding_to_loopback(self, mock_dns):
        mock_dns.return_value = self._mock_getaddrinfo("127.0.0.1")
        result = resolve_and_validate("https://evil.example.com/")
        self.assertIsNotNone(result)
        self.assertIn("127.0.0.1", result)

    @patch("socket.getaddrinfo")
    def test_blocks_dns_rebinding_to_rfc1918_10(self, mock_dns):
        mock_dns.return_value = self._mock_getaddrinfo("10.0.0.1")
        result = resolve_and_validate("https://internal-service.attacker.com/")
        self.assertIsNotNone(result)
        self.assertIn("10.0.0.1", result)

    @patch("socket.getaddrinfo")
    def test_blocks_dns_rebinding_to_rfc1918_172(self, mock_dns):
        mock_dns.return_value = self._mock_getaddrinfo("172.16.5.10")
        result = resolve_and_validate("https://steal-data.attacker.com/")
        self.assertIsNotNone(result)
        self.assertIn("172.16.5.10", result)

    @patch("socket.getaddrinfo")
    def test_blocks_dns_rebinding_to_rfc1918_192(self, mock_dns):
        mock_dns.return_value = self._mock_getaddrinfo("192.168.1.1")
        result = resolve_and_validate("https://router-pwn.attacker.com/")
        self.assertIsNotNone(result)
        self.assertIn("192.168.1.1", result)

    @patch("socket.getaddrinfo")
    def test_blocks_dns_rebinding_to_ecs_metadata(self, mock_dns):
        mock_dns.return_value = self._mock_getaddrinfo("169.254.170.2")
        result = resolve_and_validate("https://ecs-steal.attacker.com/")
        self.assertIsNotNone(result)
        self.assertIn("169.254.170.2", result)

    @patch("socket.getaddrinfo")
    def test_blocks_if_any_resolved_ip_is_internal(self, mock_dns):
        """If hostname resolves to multiple IPs and ANY is internal, block it."""
        mock_dns.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 0)),  # public
            (2, 1, 6, "", ("169.254.169.254", 0)),  # IMDS!
        ]
        result = resolve_and_validate("https://dual-homed.attacker.com/")
        self.assertIsNotNone(result)
        self.assertIn("169.254.169.254", result)

    @patch("socket.getaddrinfo")
    def test_handles_dns_failure(self, mock_dns):
        import socket

        mock_dns.side_effect = socket.gaierror("Name or service not known")
        result = resolve_and_validate("https://nonexistent.invalid/")
        self.assertIsNotNone(result)
        self.assertIn("could not be resolved", result)

    @patch("socket.getaddrinfo")
    def test_allows_multiple_public_ips(self, mock_dns):
        mock_dns.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 0)),
            (2, 1, 6, "", ("93.184.216.35", 0)),
        ]
        self.assertIsNone(resolve_and_validate("https://cdn.example.com/"))

    @patch("socket.getaddrinfo")
    def test_blocks_ipv6_link_local(self, mock_dns):
        mock_dns.return_value = [(10, 1, 6, "", ("fe80::1", 0, 0, 0))]
        result = resolve_and_validate("https://ipv6-rebind.attacker.com/")
        self.assertIsNotNone(result)
        self.assertIn("fe80::1", result)


class TestValidateUrlHardenedRanges(unittest.TestCase):
    """M1: ranges added to the hardened SSRF denylist (static validate_url)."""

    # ── Unspecified / 0.0.0.0/8 ──
    def test_rejects_unspecified_0000(self):
        r = validate_url("http://0.0.0.0/")
        self.assertIsNotNone(r)
        self.assertIn("blocked", r)

    def test_rejects_0_8_block(self):
        self.assertIsNotNone(validate_url("http://0.1.2.3/"))

    # ── CGNAT 100.64.0.0/10 (RFC 6598) ──
    def test_rejects_cgnat_100_64(self):
        r = validate_url("http://100.64.0.1/")
        self.assertIsNotNone(r)
        self.assertIn("blocked", r)

    def test_rejects_cgnat_top(self):
        self.assertIsNotNone(validate_url("http://100.127.255.255/"))

    def test_allows_100_63_public(self):
        """100.63.0.1 is outside CGNAT and is globally routable."""
        self.assertIsNone(validate_url("http://100.63.0.1/"))

    # ── IETF protocol assignments 192.0.0.0/24 (RFC 6890) ──
    def test_rejects_protocol_assignments_192_0_0_1(self):
        self.assertIsNotNone(validate_url("http://192.0.0.1/"))

    def test_rejects_protocol_assignments_192_0_0_100(self):
        """192.0.0.100 is not in a Python is_private sub-range; the explicit
        192.0.0.0/24 range must still block it."""
        r = validate_url("http://192.0.0.100/")
        self.assertIsNotNone(r)
        self.assertIn("blocked", r)

    # ── Benchmarking 198.18.0.0/15 (RFC 2544) ──
    def test_rejects_benchmark_198_18(self):
        r = validate_url("http://198.18.0.1/")
        self.assertIsNotNone(r)
        self.assertIn("blocked", r)

    def test_rejects_benchmark_198_19(self):
        self.assertIsNotNone(validate_url("http://198.19.255.255/"))

    # ── IPv6 unspecified ::/128 ──
    def test_rejects_ipv6_unspecified(self):
        self.assertIsNotNone(validate_url("http://[::]/"))

    # ── NAT64 well-known prefix 64:ff9b::/96 (RFC 6052) ──
    def test_rejects_nat64_prefix(self):
        r = validate_url("http://[64:ff9b::1]/")
        self.assertIsNotNone(r)
        self.assertIn("blocked", r)

    # ── IPv6 cloud metadata fd00:ec2::254 ──
    def test_rejects_ipv6_metadata(self):
        r = validate_url("http://[fd00:ec2::254]/latest/meta-data/")
        self.assertIsNotNone(r)
        self.assertIn("blocked", r)

    # ── IPv4-mapped IPv6 (::ffff:0:0/96): unwrap and re-check ──
    def test_rejects_ipv4_mapped_imds(self):
        r = validate_url("http://[::ffff:169.254.169.254]/")
        self.assertIsNotNone(r)
        self.assertIn("blocked", r)

    def test_rejects_ipv4_mapped_rfc1918(self):
        r = validate_url("http://[::ffff:10.0.0.1]/")
        self.assertIsNotNone(r)
        self.assertIn("blocked", r)

    def test_rejects_ipv4_mapped_loopback(self):
        self.assertIsNotNone(validate_url("http://[::ffff:127.0.0.1]/"))


class TestResolveHardenedRanges(unittest.TestCase):
    """M1: DNS-resolution checks for the hardened ranges, including multi-address."""

    def _one(self, ip_str):
        return [(2, 1, 6, "", (ip_str, 0))]

    @patch("socket.getaddrinfo")
    def test_blocks_cgnat(self, mock_dns):
        mock_dns.return_value = self._one("100.64.0.1")
        r = resolve_and_validate("https://cgnat.attacker.com/")
        self.assertIsNotNone(r)
        self.assertIn("100.64.0.1", r)

    @patch("socket.getaddrinfo")
    def test_blocks_benchmark(self, mock_dns):
        mock_dns.return_value = self._one("198.18.0.5")
        r = resolve_and_validate("https://bench.attacker.com/")
        self.assertIsNotNone(r)
        self.assertIn("198.18.0.5", r)

    @patch("socket.getaddrinfo")
    def test_blocks_all_zeros(self, mock_dns):
        mock_dns.return_value = self._one(ALL_ZEROS_V4)
        self.assertIsNotNone(resolve_and_validate("https://zero.attacker.com/"))

    @patch("socket.getaddrinfo")
    def test_blocks_ipv6_metadata(self, mock_dns):
        mock_dns.return_value = [(10, 1, 6, "", ("fd00:ec2::254", 0, 0, 0))]
        r = resolve_and_validate("https://ec2meta.attacker.com/")
        self.assertIsNotNone(r)
        self.assertIn("fd00:ec2::254", r)

    @patch("socket.getaddrinfo")
    def test_blocks_ipv4_mapped_private(self, mock_dns):
        """A hostname resolving to an IPv4-mapped private address is blocked."""
        mock_dns.return_value = [(10, 1, 6, "", ("::ffff:10.0.0.5", 0, 0, 0))]
        r = resolve_and_validate("https://mapped.attacker.com/")
        self.assertIsNotNone(r)
        self.assertIn("10.0.0.5", r)

    @patch("socket.getaddrinfo")
    def test_blocks_when_one_of_many_addresses_is_cgnat(self, mock_dns):
        """Multi-address hostname: a single internal address blocks the whole name."""
        mock_dns.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 0)),  # public
            (2, 1, 6, "", ("100.64.0.5", 0)),  # CGNAT!
        ]
        r = resolve_and_validate("https://dual.attacker.com/")
        self.assertIsNotNone(r)
        self.assertIn("100.64.0.5", r)

    @patch("socket.getaddrinfo")
    def test_strips_ipv6_zone_id_before_checking(self, mock_dns):
        mock_dns.return_value = [(10, 1, 6, "", ("fe80::1%eth0", 0, 0, 0))]
        r = resolve_and_validate("https://zoned.attacker.com/")
        self.assertIsNotNone(r)


class TestValidateUrlIntegration(unittest.TestCase):
    """Integration tests combining validate_url + resolve_and_validate flow."""

    def test_full_flow_valid_url(self):
        """A valid public URL passes validate_url (resolve needs network)."""
        self.assertIsNone(validate_url("https://www.google.com/search?q=test"))

    def test_full_flow_imds_blocked_at_validate(self):
        """IMDS IP blocked at validate_url stage, no DNS needed."""
        result = validate_url("http://169.254.169.254/latest/meta-data/iam/")
        self.assertIsNotNone(result)
        self.assertIn("blocked", result)

    def test_full_flow_credentials_blocked_at_validate(self):
        """Embedded credentials blocked at validate_url stage."""
        result = validate_url("https://admin:secret@metadata.google.internal/")
        self.assertIsNotNone(result)
        self.assertIn("credentials", result)

    def test_full_flow_port_blocked_at_validate(self):
        """Non-standard port blocked at validate_url stage."""
        result = validate_url("https://example.com:9200/")  # Elasticsearch
        self.assertIsNotNone(result)
        self.assertIn("port", result)


if __name__ == "__main__":
    unittest.main()


@pytest.mark.parametrize(
    "url",
    [
        "http://2130706433/",
        "http://0177.0.0.1/",
        "http://0x7f.1/",
        "http://127.1/",
        "http://0x7f000001/",
        "http://127.0.0.1./",
        "http://169.254.43518/",
        "http://0xa9fea9fe/",
        "http://10.1/",
        "http://0/",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:7f00:1]/",
        "http://[::ffff:169.254.169.254]/",
    ],
)
def test_numeric_ip_forms_of_blocked_addresses_are_refused_before_dns(url):
    reason = validate_url(url)
    assert reason is not None and "blocked IP address" in reason, reason


@pytest.mark.parametrize("url", ["http://1.2.3.09/", "http://256.1.1.1/", "http://1.2.3.4.5/"])
def test_hosts_that_are_neither_addresses_nor_names_are_refused(url):
    reason = validate_url(url)
    assert reason is not None and "not a valid address" in reason, reason


@pytest.mark.parametrize("url", ["http://134744072/", "http://8.8.8.8/", "https://example.com/"])
def test_public_numeric_forms_and_names_pass_the_literal_check(url):
    assert validate_url(url) is None
