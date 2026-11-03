# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import pytest

from phish_backend.common.url_key import dedup_key, normalize_url

OWNER = "arn:aws:sts::1:assumed-role/R"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("HTTPS://Example.COM", "https://example.com/"),
        ("https://example.com:443/a", "https://example.com/a"),
        ("http://example.com:80/a", "http://example.com/a"),
        ("http://example.com:443/a", "http://example.com:443/a"),
        ("https://Example.com./a?b=C", "https://example.com./a?b=C"),
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
    key = dedup_key(OWNER, "https://Example.com:443")
    assert key == dedup_key(OWNER, "https://example.com/")
    assert key != dedup_key(f"{OWNER}:user-b", "https://example.com/")
    assert key != dedup_key(OWNER, "https://example.com/?a")
    assert len(key) == 64


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("https://faß.de/x", "https://fass.de/x"),
        ("https://example.com./x", "https://example.com/x"),
        ("https://example.com/x#a", "https://example.com/x#b"),
        ("https://a@example.com/x", "https://example.com/x"),
        ("https://example.com/X", "https://example.com/x"),
        ("http://example.com/x", "https://example.com/x"),
    ],
)
def test_distinct_destinations_never_share_a_key(first, second):
    assert dedup_key(OWNER, first) != dedup_key(OWNER, second)
