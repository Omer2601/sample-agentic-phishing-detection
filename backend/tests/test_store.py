# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from backend_testkit import OWNER_A, OWNER_B

from phish_backend.common import store
from phish_contracts.models import BatchRecord, BatchSource, ScanRecord, ScanStatus, Verdict

T0 = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


def make_scan(scan_id="s1", owner=OWNER_A, batch_id=None, queued=T0):
    return ScanRecord(
        scan_id=scan_id,
        owner=owner,
        url="https://evil.example/",
        batch_id=batch_id,
        status=ScanStatus.PENDING,
        queued_at=queued,
    )


def make_verdict():
    return Verdict(
        verdict="phishing",
        risk_score=90,
        confidence="high",
        action="block",
        summary="s",
        report_markdown="# r",
    )


def test_put_is_idempotent(aws):
    assert store.put_scan_if_absent(make_scan()) is True
    assert store.put_scan_if_absent(make_scan()) is False
    assert store.get_scan("s1").status == ScanStatus.PENDING


def test_claim_sets_running_and_queue_wait(aws):
    store.put_scan_if_absent(make_scan())
    claimed = store.claim_scan("s1", "tok", T0 + timedelta(seconds=3))
    assert claimed.status == ScanStatus.RUNNING
    assert claimed.queue_wait_ms == 3000
    assert store.claim_scan("s1", "tok2", T0 + timedelta(seconds=4)) is None


def test_stale_claim_can_be_retaken(aws):
    store.put_scan_if_absent(make_scan())
    store.claim_scan("s1", "tok", T0)
    later = T0 + timedelta(seconds=store.CLAIM_LEASE_SECONDS + 1)
    assert store.claim_scan("s1", "tok2", later).status == ScanStatus.RUNNING


def test_claim_missing_raises(aws):
    with pytest.raises(store.ScanMissing):
        store.claim_scan("nope", "tok", T0)


def test_complete_requires_the_claim_token(aws):
    store.put_scan_if_absent(make_scan())
    store.claim_scan("s1", "tok", T0)
    args = dict(
        verdict=make_verdict(),
        findings=[],
        calls=[],
        cost=Decimal("0.12"),
        completed_at=T0 + timedelta(seconds=30),
        total_ms=30000,
    )
    assert store.complete_scan("s1", "wrong", **args) is False
    assert store.complete_scan("s1", "tok", **args) is True
    done = store.get_scan("s1")
    assert done.status == ScanStatus.COMPLETE
    assert done.verdict.verdict == "phishing"
    assert done.cost_usd == Decimal("0.12")


def test_history_is_owner_scoped_and_paginated(aws):
    for i in range(3):
        store.put_scan_if_absent(make_scan(f"a{i}", queued=T0 + timedelta(minutes=i)))
    store.put_scan_if_absent(make_scan("b0", owner=OWNER_B))
    page, cursor = store.scans_for_owner(OWNER_A, 2, None)
    assert [s.scan_id for s in page] == ["a2", "a1"]
    rest, end = store.scans_for_owner(OWNER_A, 2, cursor)
    assert [s.scan_id for s in rest] == ["a0"]
    assert end is None
    with pytest.raises(store.BadCursor):
        store.scans_for_owner(OWNER_B, 2, cursor)


def test_batch_counters_round_trip(aws):
    batch = BatchRecord(batch_id="b1", owner=OWNER_A, source=BatchSource.UI, total=5, created_at=T0)
    store.put_batch(batch, awaiting_upload=True)
    item = store.get_batch_item("b1")
    assert item["awaiting_upload"] is True
    # Lifecycle fields are written only by the store's own updates: a fresh item
    # must not carry split_at or error, or the split and sweeper conditions
    # (attribute_not_exists(split_at), attribute_exists(awaiting_upload)) break.
    assert "split_at" not in item and "error" not in item
    assert item["cost_usd"] == Decimal("0")
    loaded = store.get_batch("b1")
    assert loaded.status_counts[ScanStatus.PENDING] == 5
    assert loaded.awaiting_upload is True and loaded.split_at is None
    store.set_batch_total("b1", 3, [{"row": 2, "value": "x", "reason": "bad"}])
    assert store.get_batch("b1").total == 3
    assert "awaiting_upload" not in store.get_batch_item("b1")
    assert store.get_batch("b1").awaiting_upload is False
    assert store.mark_batch_split("b1", T0) is True
    assert store.get_batch("b1").split_at == T0
    assert store.mark_batch_split("b1", T0) is False


def test_bad_cursor_rejected(aws):
    with pytest.raises(store.BadCursor):
        store.scans_for_owner(OWNER_A, 2, "not-base64!!")


def test_put_batch_never_writes_awaiting_upload_false(aws):
    """The sweeper selects on attribute_exists(awaiting_upload); a stored False
    would make every JSON batch look abandoned."""
    batch = BatchRecord(
        batch_id="b2", owner=OWNER_A, source=BatchSource.API, total=1, created_at=T0
    )
    store.put_batch(batch, awaiting_upload=False)
    assert "awaiting_upload" not in store.get_batch_item("b2")
