# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Owner identity (ported from v1) and submitted-URL validation."""

import pytest

from phish_backend.common import clients, identity, url_input

PROXY_ROLE = "arn:aws:iam::123456789012:role/ProxyRole"
PROXY_CALLER = "arn:aws:sts::123456789012:assumed-role/ProxyRole/session-1"
OTHER_CALLER = "arn:aws:sts::123456789012:assumed-role/Other/session-9"


@pytest.fixture(autouse=True)
def proxy(monkeypatch):
    monkeypatch.setenv("PROXY_ROLE_ARN", PROXY_ROLE)
    clients.reset()
    yield
    clients.reset()


def event(caller, headers=None):
    return {"headers": headers or {}, "requestContext": {"identity": {"userArn": caller}}}


def test_no_arn_is_anonymous():
    assert identity.resolve_owner(event("")) == "anonymous"


def test_proxy_caller_with_valid_sub_gets_composite_key():
    owner = identity.resolve_owner(event(PROXY_CALLER, {"x-console-user-sub": "abc-123"}))
    assert owner == "arn:aws:sts::123456789012:assumed-role/ProxyRole:abc-123"


def test_header_case_insensitive():
    owner = identity.resolve_owner(event(PROXY_CALLER, {"X-Console-User-Sub": "abc-123"}))
    assert owner.endswith(":abc-123")


def test_non_proxy_caller_ignores_the_header():
    owner = identity.resolve_owner(event(OTHER_CALLER, {"x-console-user-sub": "abc-123"}))
    assert owner == "arn:aws:sts::123456789012:assumed-role/Other"


def test_proxy_caller_without_header_is_anonymous():
    # Every UI user shares the proxy role, so a role-only key would pool their scans.
    assert identity.resolve_owner(event(PROXY_CALLER)) == "anonymous"


def test_proxy_caller_with_malformed_sub_is_anonymous():
    owner = identity.resolve_owner(event(PROXY_CALLER, {"x-console-user-sub": "bad sub/../"}))
    assert owner == "anonymous"


def test_header_untrusted_when_proxy_arn_unset(monkeypatch):
    monkeypatch.setenv("PROXY_ROLE_ARN", "")
    clients.reset()
    owner = identity.resolve_owner(event(PROXY_CALLER, {"x-console-user-sub": "abc"}))
    assert owner == "arn:aws:sts::123456789012:assumed-role/ProxyRole"


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/",
        "http://paypal.com@evil.example/login",
        "https://sub.domain.example:8443/a?b=c#d",
    ],
)
def test_valid_urls_pass(url):
    assert url_input.validate_submitted_url(f"  {url} ") == url


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("", "url is required"),
        (None, "url is required"),
        (123, "url must be a string"),
        ("ftp://example.com", "url must start with http:// or https://"),
        ("javascript:alert(1)", "url must start with http:// or https://"),
        ("https://", "url has no host"),
        ("https://exa mple.com", "url contains whitespace or control characters"),
        ("http://127.0.0.1/admin", "url targets a private or reserved address"),
        ("http://10.0.0.5/", "url targets a private or reserved address"),
        ("http://169.254.169.254/latest/meta-data", "url targets a private or reserved address"),
        ("http://[::1]/", "url targets a private or reserved address"),
        ("http://localhost:8080/", "url targets a private or reserved address"),
        ("https://example.com/" + "a" * 2100, "url is longer than 2048 characters"),
    ],
)
def test_invalid_urls_rejected(url, message):
    with pytest.raises(url_input.InvalidUrl, match=message):
        url_input.validate_submitted_url(url)


def test_error_or_none_adapter():
    assert url_input.error_or_none("https://example.com") is None
    assert url_input.error_or_none("ftp://x") == "url must start with http:// or https://"
