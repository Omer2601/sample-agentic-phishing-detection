# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""CAPTURE_RECOVERY unset keeps the earlier capture behaviour."""

import asyncio
import socket
from contextlib import AsyncExitStack

import pytest
from playwright.async_api import Error as PlaywrightError

from phish_agents.common import capture_recovery, url_safety

S3_SITE = "https://bucket.s3-website-us-east-1.amazonaws.com/index.html"


@pytest.fixture
def recovery_off(monkeypatch):
    monkeypatch.delenv("CAPTURE_RECOVERY", raising=False)


def test_on_rewrites_s3_website_to_http():
    assert capture_recovery.s3_website_http_url(S3_SITE).startswith("http://")


def test_off_keeps_s3_website_url(recovery_off):
    assert capture_recovery.s3_website_http_url(S3_SITE) == S3_SITE


def test_off_does_not_retry_transient_dns(recovery_off, monkeypatch):
    calls = []

    def flaky(*_a, **_k):
        calls.append(1)
        raise socket.gaierror(socket.EAI_AGAIN, "temporary failure")

    monkeypatch.setattr(url_safety.socket, "getaddrinfo", flaky)
    with pytest.raises(socket.gaierror):
        url_safety._getaddrinfo("example.com", retry=True)
    assert len(calls) == 1


def test_off_raises_a_certificate_error_without_a_tolerant_retry(recovery_off):
    class Page:
        pass

    async def open_url(_page, _url):
        raise PlaywrightError("net::ERR_CERT_AUTHORITY_INVALID at https://self-signed.example/")

    async def run():
        async with AsyncExitStack() as stack:
            await capture_recovery.open_capture(
                stack, Page(), "https://self-signed.example/", open_url, lambda: 60_000, 1_000
            )

    with pytest.raises(PlaywrightError, match="ERR_CERT"):
        asyncio.run(run())
