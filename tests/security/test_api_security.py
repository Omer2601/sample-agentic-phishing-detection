# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Security checks against the deployed API.

Run: uv run --package phish-backend pytest -m e2e tests/security
"""

import concurrent.futures
import os

import pytest

from tests.e2e.client import ApiClient
from tests.e2e.stack import REGION, outputs

pytestmark = pytest.mark.e2e


@pytest.fixture(scope="module")
def api():
    return ApiClient(outputs()["ApiUrl"], REGION)


def test_health_is_minimal(api):
    status, body = api.request("GET", "/health", signed=False)
    assert status == 200 and body == {"ok": True}


def test_unsigned_requests_are_rejected(api):
    for method, path in (
        ("POST", "/scan"),
        ("GET", "/history"),
        ("GET", "/stats"),
        ("POST", "/batches"),
    ):
        status, _ = api.request(method, path, body={} if method == "POST" else None, signed=False)
        assert status == 403, (method, path)


@pytest.mark.parametrize(
    ("url", "fragment"),
    [
        ("ftp://example.com", "http://"),
        ("javascript:alert(1)", "http://"),
        ("", "required"),
        ("http://169.254.169.254/latest/meta-data/", "private or reserved"),
        ("http://127.0.0.1/", "private or reserved"),
        ("http://localhost/", "private or reserved"),
        ("https://example.com/" + "a" * 2100, "longer than"),
    ],
)
def test_input_validation(api, url, fragment):
    status, body = api.request("POST", "/scan", body={"url": url})
    assert status == 400 and fragment in body["error"]


def test_batch_caps(api):
    status, _ = api.request(
        "POST", "/batches", body={"urls": [f"https://h{i}.example/" for i in range(51)]}
    )
    assert status == 400
    status, _ = api.request("POST", "/batches", body={"upload": True, "count": 201, "source": "ui"})
    assert status == 400
    status, _ = api.request(
        "POST", "/batches", body={"upload": True, "count": 1001, "source": "api"}
    )
    assert status == 400


def test_forged_user_header_is_ignored_for_direct_callers(api):
    body = api.post_scan("https://example.com/")
    status, _ = api.request(
        "GET", f"/scans/{body['scan_id']}", headers={"X-Console-User-Sub": "someone-else"}
    )
    assert status == 200


def test_unknown_scan_is_404_without_detail(api):
    status, body = api.request("GET", "/scans/does-not-exist")
    assert status == 404 and "arn:" not in str(body)


@pytest.mark.skipif(os.environ.get("PHISH_SKIP_BURST") == "1", reason="burst test disabled")
def test_stage_throttling_returns_429(api):
    def hit(_):
        return api.request("GET", "/history", query={"limit": 1})[0]

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
        codes = list(pool.map(hit, range(60)))
    assert 429 in codes, codes
