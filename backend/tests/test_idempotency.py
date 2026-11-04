# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Idempotency-Key on POST /scan: replay, conflicts, races, owner scoping and the 503 release."""

import json
import time

import boto3
import pytest
from backend_testkit import DIRECT_CALLER, OWNER_A, FailingSqs, api_event, patch_sqs, utcnow

from phish_backend.api import app, idempotency
from phish_backend.common import clients, store

URL = "https://a.example/"


def post(url=URL, key="k-1", **kwargs):
    event = api_event("POST", "/scan", body={"url": url}, **kwargs)
    if key is not None:
        event["headers"]["Idempotency-Key"] = key
    response = app.handler(event, None)
    return response["statusCode"], json.loads(response["body"]), response["headers"]


def owner_scans(owner=OWNER_A):
    return store.scans_for_owner(owner, 50, None)[0]


def test_first_request_creates_and_a_retry_replays_the_same_scan(aws):
    status, first, headers = post()
    assert status == 202 and first["status"] == "PENDING"
    assert "Idempotent-Replayed" not in headers
    status, again, headers = post()
    assert status == 200 and headers["Idempotent-Replayed"] == "true"
    assert again["scan_id"] == first["scan_id"] and again["status"] == "PENDING"
    assert "disclaimer" in again
    assert len(owner_scans()) == 1


def test_a_replay_reports_the_current_status(aws):
    _, first, _ = post()
    store.fail_pending_scan(first["scan_id"], error="x", completed_at=utcnow())
    status, again, _ = post()
    assert status == 200 and again["status"] == "FAILED"


def test_the_same_key_with_a_different_url_is_422(aws):
    post()
    status, body, _ = post(url="https://b.example/")
    assert status == 422
    assert body["error"] == "Idempotency-Key was already used with a different url"
    assert len(owner_scans()) == 1


@pytest.mark.parametrize("key", ["bad key!", "", " ", "x" * 129, "a/b"])
def test_a_malformed_key_is_400_and_creates_nothing(aws, key):
    status, body, _ = post(key=key)
    assert status == 400 and body["error"] == idempotency.INVALID_KEY
    assert owner_scans() == []


def test_a_key_of_128_allowed_characters_is_accepted(aws):
    assert post(key="Aa0._:-" * 18 + "xx")[0] == 202


def test_a_claim_in_flight_is_409_with_retry_after(aws):
    idempotency.claim(OWNER_A, "k-1", "not-yet-written", URL)
    status, body, headers = post()
    assert status == 409 and headers["Retry-After"] == "2"
    assert "still being processed" in body["error"]
    assert owner_scans() == []


def test_a_dead_claim_past_the_lease_is_taken_over(aws):
    idempotency.claim(OWNER_A, "k-1", "never-written", URL, now=time.time() - 120)
    status, body, _ = post()
    assert status == 202 and body["scan_id"] != "never-written"
    assert post()[1]["scan_id"] == body["scan_id"]


def test_an_expired_claim_is_ignored(aws):
    _, first, _ = post()
    table = boto3.resource("dynamodb").Table("phish-idempotency")
    table.update_item(
        Key={"pk": f"{OWNER_A}#k-1"},
        UpdateExpression="SET expires_at = :past",
        ExpressionAttributeValues={":past": int(time.time()) - 1},
    )
    status, second, _ = post()
    assert status == 202 and second["scan_id"] != first["scan_id"]


def test_keys_are_scoped_to_the_owner(aws):
    _, a, _ = post(sub="user-a")
    status, b, _ = post(sub="user-b")
    status_direct, direct, _ = post(caller=DIRECT_CALLER, sub=None)
    # Two web users and an API caller never replay each other's scans.
    assert status == 202 and status_direct == 202
    assert len({a["scan_id"], b["scan_id"], direct["scan_id"]}) == 3


def test_a_request_that_loses_the_race_replays_the_winner(aws, monkeypatch):
    _, winner, _ = post()
    # The loser read the key before the winner's claim was written, then lost the put.
    monkeypatch.setattr(idempotency, "find", lambda *a, **k: None)
    real_claim = idempotency.claim

    def claim_after_find(*args, **kwargs):
        monkeypatch.undo()
        return real_claim(*args, **kwargs)

    monkeypatch.setattr(idempotency, "claim", claim_after_find)
    status, body, headers = post()
    assert status == 200 and headers["Idempotent-Replayed"] == "true"
    assert body["scan_id"] == winner["scan_id"]
    assert len(owner_scans()) == 1


def test_503_releases_the_key_so_the_same_key_can_retry(aws, monkeypatch):
    real = clients.sqs()
    patch_sqs(monkeypatch, FailingSqs())
    status, body, _ = post()
    assert status == 503 and body["error"] == "the scan could not be queued; try again"
    patch_sqs(monkeypatch, real)
    status, body, _ = post()
    assert status == 202
    assert sorted(s.status for s in owner_scans()) == ["FAILED", "PENDING"]


def test_without_the_header_every_request_is_a_new_scan(aws):
    post(key=None)
    post(key=None)
    assert len(owner_scans()) == 2


def test_a_deployment_without_the_table_refuses_the_header(aws, monkeypatch):
    monkeypatch.delenv("IDEMPOTENCY_TABLE")
    clients.reset()
    status, body, _ = post()
    assert status == 501 and "retry without the header" in body["error"]
    assert owner_scans() == []
    assert post(key=None)[0] == 202
