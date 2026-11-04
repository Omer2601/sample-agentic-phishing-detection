# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import pytest

from phish_backend.common.url_input import InvalidUrl, error_or_none, validate_submitted_url


def test_query_and_fragment_are_kept_verbatim():
    url = "https://a.example/p?q=%20x&e=user@example.net#frag"
    assert validate_submitted_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "http://2130706433/",  # integer 127.0.0.1
        "http://0177.0.0.1/",  # octal first octet
        "http://0x7f.1/",  # hex + short form
        "http://127.1/",  # short-dotted
        "http://0x7f000001/",  # hex integer
        "http://017700000001/",  # octal integer
        "http://127.0.0.1./",  # trailing dot
        "http://0x7F.0.0.1/",  # upper-case hex
        "http://0/",  # 0.0.0.0
        "http://10.1/",  # 10.0.0.1
        "http://192.168.257/",  # 192.168.1.1
        "http://169.254.43518/",  # 169.254.169.254 (metadata)
        "http://0xa9fea9fe/",  # 169.254.169.254 as hex
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:7f00:1]/",
        "http://[::ffff:169.254.169.254]/",
        "http://[::ffff:10.0.0.1]/",
        "http://[::1]/",
        "http://[fe80::1%25eth0]/",
    ],
)
def test_private_addresses_in_any_numeric_form_are_rejected(url):
    with pytest.raises(InvalidUrl, match="private or reserved"):
        validate_submitted_url(url)


@pytest.mark.parametrize(
    "url",
    ["http://1.2.3.09/", "http://256.1.1.1/", "http://1.2.3.4.5/", "http://1..1/"],
)
def test_hosts_that_end_in_a_number_but_are_not_addresses_are_rejected(url):
    with pytest.raises(InvalidUrl, match="not a valid address"):
        validate_submitted_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://8.8.8.8/",
        "http://134744072/",  # 8.8.8.8 as an integer
        "http://0x08080808/",
        "http://8.8.2056/",
        "https://example.com/",
        "http://1.2.3.example.com/",
        "http://[2606:4700:4700::1111]/",
    ],
)
def test_public_addresses_and_hostnames_are_accepted(url):
    assert validate_submitted_url(url) == url
    assert error_or_none(url) is None
