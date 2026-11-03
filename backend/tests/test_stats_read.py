# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import csv
import io
from datetime import UTC, datetime
from decimal import Decimal

import boto3
from backend_testkit import OWNER_A

from phish_backend.common import store
from phish_backend.stats import read
from phish_contracts.disclaimer import DISCLAIMER_TEXT
from phish_contracts.models import ScanRecord, ScanStatus

NOW = datetime(2026, 9, 29, 12, 30, tzinfo=UTC)


def put_stats(bucket, **counters):
    table = boto3.resource("dynamodb", region_name="us-west-2").Table("phish-stats")
    table.put_item(Item={"owner": OWNER_A, "bucket": bucket, **store.to_dynamo(counters)})


def test_bucket_keys():
    assert len(read.bucket_keys("24h", NOW)) == 24
    assert read.bucket_keys("24h", NOW)[-1] == ("2026-09-29T12", "hour#2026-09-29T12")
    assert read.bucket_keys("7d", NOW)[0] == ("2026-09-23", "day#2026-09-23")
    assert read.bucket_keys("all", NOW) == [("all", "all")]


def test_build_stats_totals_percentiles_and_breakdowns(aws):
    common = {
        "scanned": 10,
        "verdict#phishing": 6,
        "verdict#suspicious": 2,
        "verdict#legitimate": 1,
        "verdict#error_404": 3,
        "verdict#site_down": 2,
        "failed": 1,
        "input_tokens": 1000,
        "output_tokens": 100,
        "cost_usd": Decimal("1.5"),
        "sum_ms": 350000,
        "timed": 10,
        "lat#40000": 9,
        "lat#60000": 1,
        "model#us.anthropic.claude-opus-5-5#in": 800,
        "model#us.anthropic.claude-opus-5-5#out": 80,
        "model#us.anthropic.claude-opus-5-5#cost": Decimal("1.2"),
        "call#browser#brand_visual#count": 10,
        "call#browser#brand_visual#sum_ms": 90000,
        "call#browser#brand_visual#errors": 1,
        "call#browser#brand_visual#lat#10000": 10,
    }
    put_stats("day#2026-09-29", **common)
    put_stats("all", **common)
    out = read.build_stats(OWNER_A, "7d", NOW)
    t = out["totals"]
    assert (t["scanned"], t["phishing"], t["failed"]) == (10, 6, 1)
    assert t["avg_ms"] == 35000 and t["p95_ms"] == 60000 and t["p95_over_max"] is False
    assert t["cost_usd"] == "1.5000"
    assert out["daily"][-1]["day"] == "2026-09-29" and out["daily"][-1]["phishing"] == 6
    assert t["error_404"] == 3 and out["daily"][-1]["error_404"] == 3
    assert t["site_down"] == 2 and out["daily"][-1]["site_down"] == 2
    assert out["by_model"][0] == {
        "model_id": "us.anthropic.claude-opus-5-5",
        "input_tokens": 800,
        "output_tokens": 80,
        "cost_usd": "1.2000",
        "cost_known": True,
    }
    assert t["unpriced_scans"] == 0
    ac = out["agentcore"][0]
    assert ac == {
        "kind": "browser",
        "name": "brand_visual",
        "count": 10,
        "avg_ms": 9000,
        "p95_ms": 10000,
        "p95_over_max": False,
        "p95_bound": True,
        "errors": 1,
        "blocked": 0,
    }
    assert {h["upper_ms"] for h in out["latency_histogram"]} >= {40000, 60000}
    assert out["recent_batches"] == []


def test_empty_stats_are_zeros(aws):
    out = read.build_stats(OWNER_A, "30d", NOW)
    assert out["totals"]["scanned"] == 0 and out["totals"]["p95_ms"] == 0
    assert len(out["daily"]) == 30


def test_export_csv_is_defanged_and_injection_safe(aws):
    rec = ScanRecord(
        scan_id="s1",
        owner=OWNER_A,
        url="https://evil.example/=cmd",
        status=ScanStatus.PENDING,
        queued_at=datetime(2026, 9, 29, 12, 0, tzinfo=UTC),
    )
    store.put_scan_if_absent(rec)
    rows = list(csv.reader(io.StringIO(read.export_csv(OWNER_A, "7d", NOW))))
    assert rows[0] == read.EXPORT_COLUMNS
    assert rows[1][2] == "hxxps://evil[.]example/=cmd"
    assert rows[1][3] == "PENDING"
    assert read.EXPORT_COLUMNS[-1] == "disclaimer" and rows[1][-1] == DISCLAIMER_TEXT


def test_csv_cell_guard():
    assert read._safe_cell("=SUM(A1)") == "'=SUM(A1)"
    assert read._safe_cell("-1") == "'-1"
    assert read._safe_cell("ok") == "ok"


def test_p95_in_the_open_bucket_reports_the_last_bound_with_a_flag(aws):
    put_stats(
        "all",
        scanned=10,
        timed=10,
        sum_ms=2_000_000,
        **{"lat#60000": 1, "lat#999999999": 9},
        **{"call#harness#orchestrator#count": 2, "call#harness#orchestrator#lat#999999999": 2},
    )
    out = read.build_stats(OWNER_A, "all", NOW)
    assert out["totals"]["p95_ms"] == 120000 and out["totals"]["p95_over_max"] is True
    ac = out["agentcore"][0]
    assert ac["p95_ms"] == 120000 and ac["p95_over_max"] is True


def test_single_sample_p95_is_the_exact_duration_not_a_bucket_edge(aws):
    # The live defect: one 149 ms WHOIS call and one 35 s scan showed p95 10s and 40s.
    put_stats(
        "day#2026-09-29",
        scanned=1,
        timed=1,
        sum_ms=35000,
        **{"lat#40000": 1},
        **{
            "call#whois#whois_lookup#count": 1,
            "call#whois#whois_lookup#sum_ms": 149,
            "call#whois#whois_lookup#lat#10000": 1,
        },
    )
    out = read.build_stats(OWNER_A, "7d", NOW)
    t = out["totals"]
    assert (t["p95_ms"], t["p95_bound"], t["p95_over_max"]) == (35000, False, False)
    ac = out["agentcore"][0]
    assert (ac["p95_ms"], ac["p95_bound"], ac["p95_over_max"]) == (149, False, False)


def test_bucketed_p95_is_flagged_as_a_bound_and_never_exceeds_the_total(aws):
    put_stats(
        "day#2026-09-29",
        **{
            # Two calls, 3 s in total: the 10 s bucket edge cannot be the p95.
            "call#browser#code_analyst#count": 2,
            "call#browser#code_analyst#sum_ms": 3000,
            "call#browser#code_analyst#lat#10000": 2,
            "call#model#url_analyst#count": 20,
            "call#model#url_analyst#sum_ms": 400000,
            "call#model#url_analyst#lat#10000": 1,
            "call#model#url_analyst#lat#30000": 19,
        },
    )
    out = read.build_stats(OWNER_A, "7d", NOW)
    by_kind = {a["kind"]: a for a in out["agentcore"]}
    assert (by_kind["browser"]["p95_ms"], by_kind["browser"]["p95_bound"]) == (3000, True)
    assert (by_kind["model"]["p95_ms"], by_kind["model"]["p95_bound"]) == (30000, True)


def test_a_model_with_no_price_is_reported_as_cost_unknown_not_free(aws):
    put_stats(
        "all",
        scanned=1,
        cost_usd=Decimal("0.06"),
        unpriced_scans=1,
        **{
            "model#xx.anthropic.claude-future-9#in": 500,
            "model#xx.anthropic.claude-future-9#out": 50,
            "model#xx.anthropic.claude-future-9#cost": Decimal(0),
            "model#xx.anthropic.claude-future-9#unpriced": 1,
        },
    )
    out = read.build_stats(OWNER_A, "all", NOW)
    assert out["totals"]["unpriced_scans"] == 1
    assert out["by_model"][0]["model_id"] == "xx.anthropic.claude-future-9"
    assert out["by_model"][0]["cost_known"] is False
