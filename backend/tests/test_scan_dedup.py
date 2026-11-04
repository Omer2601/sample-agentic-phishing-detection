# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""POST /scan dedup (flagged, off by default), force, and GET /scans/lookup."""

import json
from datetime import timedelta

import pytest
from backend_testkit import DIRECT_CALLER, api_event, utcnow
from botocore.exceptions import ClientError

from phish_backend.api import app
from phish_backend.common import clients, scans, store
from phish_contracts.models import Action, ConfidenceBand, Verdict, VerdictLabel

URL = "https://a.example/"
API_OWNER = "arn:aws:sts::123456789012:assumed-role/ApiClientRole"


def call(event):
    response = app.handler(event, None)
    return response["statusCode"], json.loads(response["body"])


def submit(body=None, *, api=True, key=None):
    kwargs = {"caller": DIRECT_CALLER, "sub": None} if api else {}
    event = api_event("POST", "/scan", body=body or {"url": URL}, **kwargs)
    if key:
        event["headers"]["Idempotency-Key"] = key
    return call(event)


def lookup(query, *, api=True):
    kwargs = {"caller": DIRECT_CALLER, "sub": None} if api else {}
    return call(api_event("GET", "/scans/lookup", query=query, **kwargs))


@pytest.fixture
def dedup_on(monkeypatch):
    monkeypatch.setenv("SCAN_DEDUP_ENABLED", "1")
    clients.reset()


def complete(scan_id, *, hours_ago=0):
    done = utcnow() - timedelta(hours=hours_ago)
    verdict = Verdict(
        verdict=VerdictLabel.PHISHING,
        risk_score=91,
        confidence=ConfidenceBand.HIGH,
        action=Action.BLOCK,
        summary="s",
        report_markdown="",
    )
    store._scans().update_item(
        Key={"scan_id": scan_id},
        UpdateExpression="SET #s = :c, completed_at = :t, verdict = :v",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":c": "COMPLETE",
            ":t": done.isoformat().replace("+00:00", "Z"),
            ":v": store._dump(verdict),
        },
    )


def owned(owner=API_OWNER):
    return store.scans_for_owner(owner, 50, None)[0]


def test_dedup_is_off_by_default(aws):
    _, first = submit()
    status, second = submit()
    assert status == 202 and second["deduplicated"] is False
    assert second["scan_id"] != first["scan_id"] and len(owned()) == 2


def test_every_row_stores_a_dedup_key_even_while_dedup_is_off(aws):
    _, body = submit()
    item = store._scans().get_item(Key={"scan_id": body["scan_id"]})["Item"]
    assert len(item["dedup_key"]) == 64
    # Internal attribute: never on the wire.
    assert (
        "dedup_key"
        not in call(
            api_event(
                "GET", "/scans/{id}", path={"id": body["scan_id"]}, caller=DIRECT_CALLER, sub=None
            )
        )[1]
    )


def test_a_running_scan_is_reused(aws, dedup_on):
    _, first = submit()
    status, second = submit({"url": "HTTPS://A.example:443/"})
    assert status == 202
    assert second == {
        **second,
        "scan_id": first["scan_id"],
        "status": "PENDING",
        "deduplicated": True,
    }
    assert len(owned()) == 1


def test_a_recent_complete_scan_is_reused_an_old_one_is_not(aws, dedup_on):
    _, first = submit()
    complete(first["scan_id"], hours_ago=23)
    _, again = submit()
    assert again["scan_id"] == first["scan_id"] and again["status"] == "COMPLETE"
    complete(first["scan_id"], hours_ago=25)
    _, fresh = submit()
    assert fresh["deduplicated"] is False and fresh["scan_id"] != first["scan_id"]


def test_a_failed_scan_is_never_reused(aws, dedup_on):
    _, first = submit()
    store.fail_pending_scan(first["scan_id"], error="x", completed_at=utcnow())
    _, again = submit()
    assert again["deduplicated"] is False and again["scan_id"] != first["scan_id"]


def test_force_bypasses_dedup_and_must_be_a_boolean(aws, dedup_on):
    _, first = submit()
    _, forced = submit({"url": URL, "force": True})
    assert forced["deduplicated"] is False and forced["scan_id"] != first["scan_id"]
    status, body = submit({"url": URL, "force": "yes"})
    assert status == 400 and body["error"] == "force must be a boolean"


def test_dedup_is_per_owner(aws, dedup_on):
    _, mine = submit()
    _, theirs = call(api_event("POST", "/scan", body={"url": URL}, sub="user-b"))
    assert theirs["scan_id"] != mine["scan_id"]


def test_the_web_console_is_never_deduplicated(aws, dedup_on):
    _, first = submit(api=False)
    status, second = submit(api=False)
    assert status == 202 and second["deduplicated"] is False
    assert second["scan_id"] != first["scan_id"]


def test_a_dedup_lookup_failure_is_a_miss_not_an_error(aws, dedup_on, monkeypatch):
    def broken(*_a, **_k):
        raise ClientError({"Error": {"Code": "ValidationException", "Message": "x"}}, "Query")

    monkeypatch.setattr(store, "iter_scans_by_dedup_key", broken)
    status, body = submit()
    assert status == 202 and body["deduplicated"] is False


def test_an_unreadable_row_is_skipped(aws, dedup_on, monkeypatch):
    _, first = submit()
    real = store.get_scan

    def flaky(scan_id, **kwargs):
        if scan_id == first["scan_id"]:
            raise ValueError("bad row")
        return real(scan_id, **kwargs)

    monkeypatch.setattr(store, "get_scan", flaky)
    status, body = submit()
    assert status == 202 and body["deduplicated"] is False


def test_an_idempotency_replay_wins_over_force_and_reports_deduplicated(aws, dedup_on):
    _, first = submit()
    _, reused = submit(key="k1")
    assert reused["scan_id"] == first["scan_id"] and reused["deduplicated"] is True
    status, replay = submit({"url": URL, "force": True}, key="k1")
    assert status == 200 and replay["scan_id"] == first["scan_id"]
    assert replay["deduplicated"] is True


def test_dedup_rereads_are_bounded(aws, dedup_on, monkeypatch):
    for _ in range(5):
        submit({"url": URL, "force": True})
    reads = []
    # Every nominated row has vanished, so each candidate costs a re-read and none matches.
    monkeypatch.setattr(store, "get_scan", lambda sid, **_k: reads.append(sid))
    assert scans.find_reusable(API_OWNER, URL) is None
    assert len(reads) == scans.DEDUP_MAX_REREADS


# ---- GET /scans/lookup ---------------------------------------------------------------


def test_lookup_miss(aws):
    status, body = lookup({"url": URL})
    assert status == 200 and body["found"] is False and body["url"] == URL
    assert "disclaimer" in body


def test_lookup_returns_the_latest_scan_and_works_with_dedup_off(aws):
    _, older = submit()
    complete(older["scan_id"], hours_ago=2)
    _, newer = submit({"url": "https://A.example"})
    status, body = lookup({"url": URL})
    assert status == 200 and body["found"] is True
    assert body["scan_id"] == newer["scan_id"] and body["status"] == "PENDING"
    assert body["verdict"] is None and body["risk_score"] is None and body["confidence"] is None
    assert body["age_seconds"] >= 0 and body["queued_at"]
    complete(newer["scan_id"], hours_ago=1)
    _, body = lookup({"url": URL})
    assert body["verdict"] == "phishing" and body["risk_score"] == 91
    assert body["confidence"] == "high" and 3500 <= body["age_seconds"] <= 3700


def test_lookup_skips_failed_unless_asked(aws):
    _, scan = submit()
    store.fail_pending_scan(scan["scan_id"], error="x", completed_at=utcnow())
    assert lookup({"url": URL})[1]["found"] is False
    for value in ("true", "1", "TRUE"):
        body = lookup({"url": URL, "include_failed": value})[1]
        assert body["found"] is True and body["status"] == "FAILED"


def test_lookup_is_per_owner(aws):
    submit()
    assert lookup({"url": URL}, api=False)[1]["found"] is False


@pytest.mark.parametrize(
    ("query", "error"),
    [
        (None, "url is required"),
        ({"url": "ftp://x"}, "url must start with http:// or https://"),
        ({"url": "http://10.0.0.1/"}, "url targets a private or reserved address"),
        ({"url": URL, "include_failed": "yes"}, "include_failed must be true or false"),
    ],
)
def test_lookup_validates_its_query(aws, query, error):
    status, body = lookup(query)
    assert status == 400 and body["error"] == error


def test_lookup_answers_not_found_while_the_index_backfills(aws, monkeypatch):
    def backfilling(*_a, **_k):
        raise ClientError(
            {
                "Error": {
                    "Code": "ValidationException",
                    "Message": "Cannot read from backfilling global secondary index",
                }
            },
            "Query",
        )

    monkeypatch.setattr(store, "iter_scans_by_dedup_key", backfilling)
    assert lookup({"url": URL})[1]["found"] is False


def test_lookup_needs_an_identity(aws):
    status, _ = call(api_event("GET", "/scans/lookup", query={"url": URL}, caller="", sub=None))
    assert status == 403
