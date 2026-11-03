# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Regression tests for DNS resolution failures in the SSRF guard.

WHY THIS FILE EXISTS
`resolve_and_validate` caught `socket.gaierror` and `OSError`, which between them
look exhaustive and are not. `socket.getaddrinfo` also raises `UnicodeError`
through the IDNA codec when a DNS label exceeds 63 characters, and `UnicodeError`
subclasses `ValueError`, so it escaped both branches. Measured against the
deployed API: the caller received HTTP 502 with `{"message": "Internal server
error"}` and no correlation id, and the same code path serves the single scan, the
batch, the CSV batch and the worker.

The assertions here are deliberately about the CONTRACT rather than the wording:
this function returns a string to reject and None to allow, so "does not raise"
and "returns a rejection" are the two properties that matter.
"""

from __future__ import annotations

import socket

import pytest

from phish_agents.common import url_safety as ssrf


def test_over_long_dns_label_is_rejected_not_raised() -> None:
    """A 64-character label is the exact input that returned 502 in production."""
    host = "a" * 64
    verdict = ssrf.resolve_and_validate(f"https://{host}.com")
    assert verdict is not None, "an unresolvable malformed host must be refused"
    assert "63" in verdict, "the message should say what the real limit is"


def test_unicode_error_from_the_resolver_is_handled(monkeypatch) -> None:
    """Pinned at the seam, so the fix cannot regress if the codec path changes.

    Raising UnicodeError directly proves the branch exists, independently of
    whether any particular hostname still triggers it in a future Python.
    """

    def raise_unicode(*_args: object, **_kwargs: object) -> None:
        raise UnicodeError("label empty or too long")

    monkeypatch.setattr(ssrf.socket, "getaddrinfo", raise_unicode)
    verdict = ssrf.resolve_and_validate("https://example.com")
    assert verdict is not None


def test_unicode_error_is_not_an_oserror() -> None:
    """The reason the original except chain could not have caught it.

    If this ever fails, UnicodeError has been rebased onto OSError and the
    dedicated branch is redundant rather than load-bearing.
    """
    assert issubclass(UnicodeError, ValueError)
    assert not issubclass(UnicodeError, OSError)


@pytest.mark.parametrize("error", [socket.gaierror(-2, "nodename"), OSError(16, "busy")])
def test_existing_resolver_branches_still_refuse(monkeypatch, error: Exception) -> None:
    """The two pre-existing branches must keep working after the insertion."""

    def raise_it(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(ssrf.socket, "getaddrinfo", raise_it)
    assert ssrf.resolve_and_validate("https://example.com") is not None
