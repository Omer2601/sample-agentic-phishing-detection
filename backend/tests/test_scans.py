# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json

import boto3
from backend_testkit import OWNER_A

from phish_backend.common import scans, store


def drain(queue_url):
    sqs = boto3.client("sqs", region_name="us-west-2")
    bodies = []
    while True:
        msgs = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10).get("Messages", [])
        if not msgs:
            return bodies
        for m in msgs:
            bodies.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])


def test_creates_rows_and_one_message_each(aws):
    records = [
        scans.new_scan(OWNER_A, f"https://e{i}.example/", batch_id="b1", scan_id=f"s{i}")
        for i in range(23)
    ]
    assert scans.create_and_enqueue(records) == 23
    bodies = drain(aws["queue_url"])
    assert sorted(b["scan_id"] for b in bodies) == sorted(f"s{i}" for i in range(23))
    assert bodies[0].keys() == {"scan_id", "owner", "url", "batch_id"}
    assert store.get_scan("s0").status == "PENDING"


def test_rerun_requeues_only_pending_rows(aws):
    records = [
        scans.new_scan(OWNER_A, "https://a.example/", scan_id="x1"),
        scans.new_scan(OWNER_A, "https://b.example/", scan_id="x2"),
    ]
    scans.create_and_enqueue(records)
    drain(aws["queue_url"])
    from datetime import UTC, datetime

    store.claim_scan("x1", "tok", datetime.now(UTC))
    assert scans.create_and_enqueue(records) == 1
    assert [b["scan_id"] for b in drain(aws["queue_url"])] == ["x2"]


def raw(scan_id):
    return (
        boto3.resource("dynamodb", region_name="us-west-2")
        .Table("phish-scans")
        .get_item(Key={"scan_id": scan_id})["Item"]
    )


def test_successful_send_stamps_enqueued_at(aws):
    scans.create_and_enqueue([scans.new_scan(OWNER_A, "https://a.example/", scan_id="e1")])
    assert int(raw("e1")["enqueued_at"]) > 0


def test_failed_send_leaves_no_enqueued_at(aws, monkeypatch):
    import pytest
    from backend_testkit import FailingSqs, patch_sqs

    for fake in (FailingSqs(), FailingSqs(raise_error=True)):
        patch_sqs(monkeypatch, fake)
        record = scans.new_scan(OWNER_A, "https://a.example/", scan_id=f"f{fake.raise_error}")
        with pytest.raises(scans.EnqueueError):
            scans.create_and_enqueue([record])
        assert "enqueued_at" not in raw(record.scan_id)
