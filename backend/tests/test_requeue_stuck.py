# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json
from datetime import UTC, datetime, timedelta

import boto3
import pytest
from backend_testkit import OWNER_A
from botocore.exceptions import ClientError
from test_scans import drain

from phish_backend.common import scans, store
from phish_backend.worker import requeue_stuck
from phish_contracts.models import BatchRecord, BatchSource

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


def table(name):
    return boto3.resource("dynamodb", region_name="us-west-2").Table(name)


def put_scan(scan_id, *, status="PENDING", queued=NOW - timedelta(hours=1), enqueued=None):
    record = scans.new_scan(OWNER_A, f"https://{scan_id}.example/", scan_id=scan_id, now=queued)
    store.put_scan_if_absent(record)
    names, values, sets = {"#s": "status"}, {":s": status}, ["#s = :s"]
    if enqueued is not None:
        sets.append("enqueued_at = :e")
        values[":e"] = int(enqueued.timestamp())
    table("phish-scans").update_item(
        Key={"scan_id": scan_id},
        UpdateExpression="SET " + ", ".join(sets),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )


def test_requeues_only_pending_scans_that_were_never_sent_or_went_quiet(aws):
    put_scan("never-sent")
    put_scan("quiet", enqueued=NOW - timedelta(minutes=21))
    put_scan("waiting", enqueued=NOW - timedelta(minutes=5))
    put_scan("just-created", queued=NOW - timedelta(seconds=30))
    put_scan("running", status="RUNNING")
    put_scan("done", status="COMPLETE")
    out = requeue_stuck.sweep(NOW)
    assert out["requeued"] == 2
    assert sorted(b["scan_id"] for b in drain(aws["queue_url"])) == ["never-sent", "quiet"]
    stamped = table("phish-scans").get_item(Key={"scan_id": "never-sent"})["Item"]
    assert int(stamped["enqueued_at"]) > 0


def test_sweep_is_idempotent(aws):
    later = datetime.now(UTC)  # enqueued_at is stamped with the real clock
    put_scan("never-sent", queued=later - timedelta(hours=1))
    assert requeue_stuck.sweep(later)["requeued"] == 1
    assert requeue_stuck.sweep(later)["requeued"] == 0
    assert [b["scan_id"] for b in drain(aws["queue_url"])] == ["never-sent"]


def test_user_retry_waits_out_the_send_grace(aws):
    put_scan("retried")
    table("phish-scans").update_item(
        Key={"scan_id": "retried"},
        UpdateExpression="SET retried_at = :r",
        ExpressionAttributeValues={":r": (NOW - timedelta(seconds=20)).isoformat()},
    )
    assert requeue_stuck.sweep(NOW)["requeued"] == 0


def upload_batch(batch_id, created):
    store.put_batch(
        BatchRecord(
            batch_id=batch_id, owner=OWNER_A, source=BatchSource.UI, total=5, created_at=created
        ),
        awaiting_upload=True,
    )


def test_uploads_that_never_arrived_fail_with_a_reason(aws):
    upload_batch("old", NOW - timedelta(minutes=31))
    upload_batch("fresh", NOW - timedelta(minutes=10))
    upload_batch("split", NOW - timedelta(hours=2))
    store.set_batch_total("split", 3, [])
    out = requeue_stuck.sweep(NOW)
    assert out["abandoned_uploads"] == 1
    old = store.get_batch_item("old")
    assert old["error"] == "CSV was never uploaded" and "completed_at" in old
    assert "awaiting_upload" not in old
    assert "error" not in store.get_batch_item("fresh")
    assert "error" not in store.get_batch_item("split")
    # A late S3 event for the abandoned batch is ignored (split_at is set).
    assert "split_at" in old


def test_handler_runs_the_sweep(aws):
    put_scan("never-sent", queued=datetime.now(UTC) - timedelta(hours=1))
    out = requeue_stuck.handler({}, None)
    assert out["requeued"] == 1
    assert json.loads(json.dumps(out)) == out


def test_sweep_queries_the_status_index_and_never_scans_the_scans_table(aws, monkeypatch):
    # Cost scales with scans in flight: 500 finished scans and 2 pending ones are stored,
    # and the sweep must read only the pending ones.
    for i in range(500):
        put_scan(f"done-{i}", status="COMPLETE")
    put_scan("never-sent")
    record = scans.new_scan(
        OWNER_A,
        "https://b.example/",
        scan_id="in-batch",
        batch_id="b1",
        now=NOW - timedelta(hours=1),
    )
    store.put_scan_if_absent(record)
    calls = []
    real = store._scans

    class Spy:
        def __init__(self, table):
            self.table = table

        def scan(self, **kwargs):
            raise AssertionError("the sweeper must not Scan the scans table")

        def query(self, **kwargs):
            response = self.table.query(**kwargs)
            calls.append((kwargs["IndexName"], len(response["Items"])))
            return response

        def __getattr__(self, name):
            return getattr(self.table, name)

    monkeypatch.setattr(store, "_scans", lambda: Spy(real()))
    assert requeue_stuck.sweep(NOW)["requeued"] == 2
    assert calls == [("status-queued_at", 2)]
    sent = {b["scan_id"]: b for b in drain(aws["queue_url"])}
    # The projected fields are enough to rebuild the worker's message.
    assert sent["in-batch"] == {
        "scan_id": "in-batch",
        "owner": OWNER_A,
        "url": "https://b.example/",
        "batch_id": "b1",
    }


def test_pending_index_follows_every_status_change(aws):
    put_scan("s", enqueued=NOW - timedelta(minutes=30))
    assert [i["scan_id"] for i in store.pending_scan_items()] == ["s"]
    put_scan("s", status="RUNNING")
    assert list(store.pending_scan_items()) == []
    put_scan("s", status="PENDING")
    assert [i["scan_id"] for i in store.pending_scan_items()] == ["s"]


def _client_error(code, message):
    return ClientError({"Error": {"Code": code, "Message": message}}, "Query")


def test_backfilling_status_index_skips_the_requeue_with_one_warning(aws, monkeypatch, caplog):
    # Seen on the 2026-10-21 deploy that added the index: 5 sweeps failed until it was ACTIVE.
    put_scan("never-sent")
    real = store._scans

    class Backfilling:
        def query(self, **kwargs):
            raise _client_error(
                "ValidationException",
                "Cannot read from backfilling global secondary index: status-queued_at",
            )

        def __getattr__(self, name):
            return getattr(real(), name)

    monkeypatch.setattr(store, "_scans", lambda: Backfilling())
    caplog.set_level("INFO", logger=requeue_stuck.__name__)
    out = requeue_stuck.sweep(NOW)
    assert out == {"requeued": 0, "not_queued": 0, "abandoned_uploads": 0, "index_ready": False}
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1 and "backfilling" in warnings[0].getMessage()
    assert not [r for r in caplog.records if r.levelno >= 40]
    assert drain(aws["queue_url"]) == []
    monkeypatch.setattr(store, "_scans", real)
    assert requeue_stuck.sweep(NOW)["requeued"] == 1


def test_other_validation_errors_still_fail_the_sweep(aws, monkeypatch):
    class Broken:
        def query(self, **kwargs):
            raise _client_error(
                "ValidationException", "The table does not have the specified index"
            )

    monkeypatch.setattr(store, "_scans", lambda: Broken())
    with pytest.raises(ClientError):
        requeue_stuck.sweep(NOW)
