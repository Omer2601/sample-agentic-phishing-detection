# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import os

os.environ.setdefault("AWS_REGION", "us-west-2")
os.environ.setdefault("ARTIFACTS_BUCKET", "test-artifacts")
# The capture fixes are behind -c captureRecovery; most tests exercise them on.
# test_capture_recovery_flag.py covers the off path.
os.environ.setdefault("CAPTURE_RECOVERY", "1")

# boto3 resolves credentials when a client is created. Static fake keys and empty
# config files stop it from running a credential_process, so no test reaches AWS.
# moto's documented placeholder; the secret key reuses it so no credential-like literal exists.
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = os.environ["AWS_ACCESS_KEY_ID"]
os.environ.pop("AWS_SESSION_TOKEN", None)
os.environ.pop("AWS_PROFILE", None)
os.environ["AWS_CONFIG_FILE"] = os.devnull
os.environ["AWS_SHARED_CREDENTIALS_FILE"] = os.devnull
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"

import socket  # noqa: E402

import pytest  # noqa: E402


@pytest.fixture
def public_dns(monkeypatch):
    """Every hostname resolves to one public address, so SSRF checks run without DNS."""
    from phish_agents.common import url_safety

    def fake_getaddrinfo(host, *_a, **_k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(url_safety.socket, "getaddrinfo", fake_getaddrinfo)
    url_safety.request_allowed.cache_clear()
    yield
    url_safety.request_allowed.cache_clear()


@pytest.fixture(autouse=True)
def no_redirect_probe(monkeypatch):
    """url_analyst's redirect probe never reaches the network in tests: one hop, HTTP 200."""
    from phish_agents.url_analyst import agent as url_agent

    async def fake_probe(url, *, total_s=None, transport=None):
        return {
            "outcome": "ok",
            "final_status": 200,
            "final_url": url,
            "hops": [url],
            "reason": "HTTP 200",
            "body_bytes": 0,
        }

    monkeypatch.setattr(url_agent, "http_probe", fake_probe)


@pytest.fixture(autouse=True)
def no_static_html_probe(monkeypatch):
    """code_analyst's raw HTML fallback never reaches the network in tests: nothing answers."""
    from phish_agents.code_analyst import capture

    async def fake_probe(url, *, total_s=None, keep_body=False):
        return {"outcome": "unreachable", "final_status": None, "final_url": url, "hops": [url]}

    monkeypatch.setattr(capture, "http_probe", fake_probe)
