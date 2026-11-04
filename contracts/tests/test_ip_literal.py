# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import ipaddress
import socket

import pytest

from phish_contracts.ip_literal import AmbiguousIpLiteral, parse_ip_literal, unwrap_mapped

NUMERIC_FORMS = [
    ("2130706433", "127.0.0.1"),
    ("0177.0.0.1", "127.0.0.1"),
    ("0x7f.1", "127.0.0.1"),
    ("127.1", "127.0.0.1"),
    ("0x7f000001", "127.0.0.1"),
    ("017700000001", "127.0.0.1"),
    ("0X7F.0.0.1", "127.0.0.1"),
    ("10.1", "10.0.0.1"),
    ("192.168.257", "192.168.1.1"),
    ("169.254.43518", "169.254.169.254"),
    # The unspecified address, built from its integer so no bind-all string literal appears.
    ("0", str(ipaddress.IPv4Address(0))),
    ("0x", str(ipaddress.IPv4Address(0))),
    ("134744072", "8.8.8.8"),
    ("8.8.8.8", "8.8.8.8"),
    ("4294967295", "255.255.255.255"),
]


@pytest.mark.parametrize(("host", "address"), NUMERIC_FORMS)
def test_numeric_ipv4_forms_parse_to_the_address_they_spell(host, address):
    assert parse_ip_literal(host) == ipaddress.IPv4Address(address)


@pytest.mark.parametrize(("host", "address"), [h for h in NUMERIC_FORMS if h[0] != "0x"])
def test_parsing_matches_the_os_resolver(host, address):
    # getaddrinfo reads numeric hosts with inet_aton; the parser must agree with it.
    assert parse_ip_literal(host) == ipaddress.IPv4Address(socket.inet_aton(host))


def test_one_trailing_dot_is_allowed_as_in_a_url_host():
    assert parse_ip_literal("127.0.0.1.") == ipaddress.IPv4Address("127.0.0.1")


@pytest.mark.parametrize("host", ["1.2.3.09", "256.1.1.1", "1.2.3.4.5", "4294967296", "1..1", "08"])
def test_hosts_ending_in_a_number_that_are_not_addresses_are_ambiguous(host):
    with pytest.raises(AmbiguousIpLiteral):
        parse_ip_literal(host)


@pytest.mark.parametrize("host", ["example.com", "1.2.3.example.com", "0x1g", "localhost", "a1"])
def test_domain_names_are_not_addresses(host):
    assert parse_ip_literal(host) is None


@pytest.mark.parametrize(
    ("host", "inner"),
    [
        ("::ffff:127.0.0.1", "127.0.0.1"),
        ("::ffff:7f00:1", "127.0.0.1"),
        ("::ffff:169.254.169.254", "169.254.169.254"),
    ],
)
def test_ipv4_mapped_ipv6_is_unwrapped(host, inner):
    address = parse_ip_literal(host)
    assert isinstance(address, ipaddress.IPv6Address)
    assert unwrap_mapped(address) == ipaddress.IPv4Address(inner)


def test_ipv6_zone_is_ignored_and_bad_ipv6_is_ambiguous():
    assert parse_ip_literal("fe80::1%eth0") == ipaddress.IPv6Address("fe80::1")
    with pytest.raises(AmbiguousIpLiteral):
        parse_ip_literal("fe80::zz")


def test_unwrap_leaves_other_addresses_alone():
    v4 = ipaddress.IPv4Address("8.8.8.8")
    v6 = ipaddress.IPv6Address("2606:4700:4700::1111")
    assert unwrap_mapped(v4) is v4 and unwrap_mapped(v6) is v6
