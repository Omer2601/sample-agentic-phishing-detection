# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import pytest

from phish_backend.common.url_key import dedup_key, normalize_url


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("HTTPS://Example.COM", "https://example.com/"),
        ("https://example.com:443/a", "https://example.com/a"),
        ("http://example.com:80/a", "http://example.com/a"),
        ("http://example.com:443/a", "http://example.com:443/a"),
        ("https://Example.com./a?b=C", "https://example.com./a?b=C"),
        ("https://Bücher.example/x", "https://xn--bcher-kva.example/x"),
        ("https://CAFÉ.Example/x", "https://xn--caf-dma.example/x"),
        ("https://faß.de/x", "https://xn--fa-hia.de/x"),
        ("https://café.example:443/x", "https://xn--caf-dma.example/x"),
        ("https://café.example./x", "https://xn--caf-dma.example./x"),
        # IDNA 2008 rejects U+2603; the host falls back to plain lowercasing.
        ("https://\u2603-Bad.example/x", "https://\u2603-bad.example/x"),
        # IPvFuture (refused at submission anyway): Python 3.13 parses it, so its case folds.
        ("https://[V1.FE]/x", "https://[v1.fe]/x"),
        ("https://example.com/A/b?Q=1#/Login", "https://example.com/A/b?Q=1#/Login"),
        ("https://User:Pw@Example.com:8443/", "https://User:Pw@example.com:8443/"),
        ("https://[2001:DB8::1]:443/", "https://[2001:db8::1]/"),
        ("  https://example.com/x  ", "https://example.com/x"),
        ("https://example.com:99999/", "https://example.com:99999/"),
    ],
)
def test_normalize_url(raw, expected):
    assert normalize_url(raw) == expected


def test_dedup_key_is_per_owner_and_spelling_insensitive():
    owner = "arn:aws:sts::1:assumed-role/R"
    key = dedup_key(owner, "https://Example.com:443")
    assert key == dedup_key(owner, "https://example.com/")
    assert key != dedup_key("arn:aws:sts::1:assumed-role/Other", "https://example.com/")
    assert key != dedup_key(owner, "https://example.com/?a")
    assert len(key) == 64


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("https://faß.de/x", "https://fass.de/x"),
        ("https://ς.gr/x", "https://σ.gr/x"),
        ("https://example.com./x", "https://example.com/x"),
        ("https://[v1.fe]/x", "https://v1.fe/x"),
        ("http://example.com/x", "https://example.com/x"),
        ("https://example.com/x#a", "https://example.com/x#b"),
        ("https://a@example.com/x", "https://example.com/x"),
        ("https://example.com/X", "https://example.com/x"),
    ],
)
def test_distinct_destinations_never_share_a_key(first, second):
    owner = "arn:aws:sts::1:assumed-role/R"
    assert normalize_url(first) != normalize_url(second)
    assert dedup_key(owner, first) != dedup_key(owner, second)


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("https://café.example/x", "https://xn--caf-dma.example/x"),
        ("https://CAFÉ.example/x", "https://xn--CAF-dma.EXAMPLE/x"),
        ("https://bücher.example/x", "https://xn--bcher-kva.example/x"),
        ("https://BÜCHER.Example/x", "https://bücher.example/x"),
    ],
)
def test_unicode_and_punycode_hosts_share_a_key(first, second):
    owner = "arn:aws:sts::1:assumed-role/R"
    assert normalize_url(first) == normalize_url(second)
    assert dedup_key(owner, first) == dedup_key(owner, second)


@pytest.mark.parametrize(
    "host",
    [
        "\u2603-bad.example",
        "a\u200db.example",
        "xn--ab\u00fc.example",
        "café..example",
    ],
)
def test_invalid_idna_host_falls_back_to_lowercase(host):
    upper = host.upper()
    assert normalize_url(f"https://{upper}/p") == f"https://{upper.lower()}/p"
