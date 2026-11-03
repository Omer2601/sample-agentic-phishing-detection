# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""End-to-end runs against the deployed stack. Needs PHISH_E2E_DATA_DIR (for example ~/Desktop).

uv run --package phish-backend pytest -m e2e tests/e2e -q
"""

import time
import urllib.request

import pytest

from tests.e2e import client, datasets, report
from tests.e2e.client import ApiClient
from tests.e2e.run_batch import run
from tests.e2e.stack import REGION, outputs

pytestmark = pytest.mark.e2e
MAX_FAILURE_RATE = 0.02


def need(name):
    if not (datasets.data_dir() / name).exists():
        pytest.skip(f"{name} not found in {datasets.data_dir()}")
    return datasets.load(name)


def assert_healthy(summary, expected):
    assert summary["error"] is None
    assert summary["submitted"] == expected
    failed = summary["status"].get("FAILED", 0)
    assert failed <= max(1, int(expected * MAX_FAILURE_RATE)), summary["failures"]
    # No scan is dropped (design 2.7): submitted == COMPLETE + FAILED, every FAILED has a reason.
    assert summary["status"].get("COMPLETE", 0) + failed == expected
    assert "" not in summary["failures"], "a FAILED scan has no reason"


@pytest.mark.parametrize("path", ["/auth/config", "/welcome"])
def test_web_tier_serves_public_routes(path):
    # The API runs bypass the web Lambda, so a broken web auth config (503 on every page,
    # UI e2e 2026-09-29) is only visible through the CloudFront URL.
    # open_https uses an https-only opener (no file: or ftp: handlers), like ApiClient.
    req = urllib.request.Request(outputs()["WebUrl"].rstrip("/") + path)  # noqa: S310 - https only, checked by open_https
    with client.open_https(req, timeout=30) as resp:
        assert resp.status == 200, (path, resp.status)


def test_single_scan_latency():
    api = ApiClient(outputs()["ApiUrl"], REGION)
    started = time.monotonic()
    scan = api.wait_scan(api.post_scan("https://example.com/")["scan_id"], timeout_s=300)
    assert scan["status"] == "COMPLETE", scan.get("error")
    assert {c["kind"] for c in scan["calls"]} >= {"harness", "specialist", "browser"}
    report.write(report.summarize("single", [scan], int((time.monotonic() - started) * 1000)))
    assert scan["total_ms"] <= 60000, "single scan slower than 60 s (target 30 to 40 s)"


@pytest.mark.parametrize(
    "name", ["Book1-smoke5.csv", "Book1-smoke5-nohdr.csv", "Book1-smoke5-crlf.csv"]
)
def test_smoke_variants(name):
    data = need(name)
    assert datasets.count_urls(data) == 5
    assert_healthy(run(name.removesuffix(".csv"), data, "ui", 900), 5)


@pytest.mark.parametrize("name", [f"Book1-chunk{i}.csv" for i in range(1, 5)])
def test_chunks(name):
    data = need(name)
    expected = datasets.count_urls(data)
    assert_healthy(run(name.removesuffix(".csv"), data, "api", 1800), expected)


def test_ui_path_200():
    data = need("Book1-clean-header.csv")
    expected = datasets.count_urls(data)
    assert expected <= 200
    summary = run("ui-200", data, "ui", 2400)
    assert_healthy(summary, expected)
    stats = ApiClient(outputs()["ApiUrl"], REGION).stats("24h")
    assert stats["totals"]["scanned"] >= expected


def test_api_1000():
    need("Book1-clean-nohdr.csv")
    data = ("\n".join(datasets.unique_urls(1000)) + "\n").encode()
    summary = run("api-1000", data, "api", 5400)
    assert_healthy(summary, 1000)
