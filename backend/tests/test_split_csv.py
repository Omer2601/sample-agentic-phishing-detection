# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import os
from datetime import UTC, datetime

import boto3
from backend_testkit import OWNER_A

from phish_backend.batch import split_csv
from phish_backend.common import store
from phish_contracts.models import BatchRecord, BatchSource


def upload(key, body, *, batch_id="b1", owner=OWNER_A, source="ui"):
    boto3.client("s3", region_name="us-west-2").put_object(
        Bucket=os.environ["UPLOAD_BUCKET"],
        Key=key,
        Body=body,
        ContentType="text/csv",
        Metadata={"batch-id": batch_id, "owner": owner, "source": source},
    )


def s3_event(key):
    return {
        "Records": [
            {"s3": {"bucket": {"name": os.environ["UPLOAD_BUCKET"]}, "object": {"key": key}}}
        ]
    }


def new_batch(batch_id="b1", count=5):
    store.put_batch(
        BatchRecord(
            batch_id=batch_id,
            owner=OWNER_A,
            source=BatchSource.UI,
            total=count,
            created_at=datetime.now(UTC),
        ),
        awaiting_upload=True,
    )


def test_split_creates_scans_and_sets_total(aws):
    new_batch()
    upload("uploads/h/b1.csv", b"url\r\nhttps://a.example/\r\nhttps://b.example/\r\nftp://x\r\n")
    split_csv.handler(s3_event("uploads/h/b1.csv"), None)
    batch = store.get_batch("b1")
    assert batch.total == 2
    items, _ = store.scans_for_batch("b1", 10, None)
    assert {s.url for s in items} == {"https://a.example/", "https://b.example/"}
    assert store.get_batch_item("b1")["invalid_rows"][0]["row"] == 4


def test_split_is_idempotent(aws):
    new_batch()
    upload("uploads/h/b1.csv", b"https://a.example/\n")
    split_csv.handler(s3_event("uploads/h/b1.csv"), None)
    split_csv.handler(s3_event("uploads/h/b1.csv"), None)
    items, _ = store.scans_for_batch("b1", 10, None)
    assert len(items) == 1


def test_owner_mismatch_is_ignored(aws):
    new_batch()
    upload("uploads/h/b1.csv", b"https://a.example/\n", owner="someone-else")
    split_csv.handler(s3_event("uploads/h/b1.csv"), None)
    assert store.scans_for_batch("b1", 10, None)[0] == []


def test_over_cap_marks_error(aws):
    new_batch()
    body = "\n".join(f"https://h{i}.example/" for i in range(201)).encode()
    upload("uploads/h/b1.csv", body, source="ui")
    split_csv.handler(s3_event("uploads/h/b1.csv"), None)
    item = store.get_batch_item("b1")
    assert "limit" in item["error"]
    assert item["total"] == 0


def test_malformed_csv_marks_the_batch_failed_without_raising(aws):
    new_batch()
    upload("uploads/h/b1.csv", b'"' + b"a" * 200_000 + b'"\n')
    split_csv.handler(s3_event("uploads/h/b1.csv"), None)  # must not raise (no S3 retry)
    item = store.get_batch_item("b1")
    assert "not a readable CSV" in item["error"] and "completed_at" in item


def test_non_utf8_csv_marks_the_batch_failed(aws):
    new_batch()
    upload("uploads/h/b1.csv", b"https://a.example/\n\xff\xfe\xfa\n")
    split_csv.handler(s3_event("uploads/h/b1.csv"), None)
    assert "UTF-8" in store.get_batch_item("b1")["error"]


def test_parser_csv_error_is_caught_in_split(aws, monkeypatch):
    import csv

    def broken(data, cap):
        raise csv.Error("line contains NUL")

    new_batch()
    upload("uploads/h/b1.csv", b"https://a.example/\n")
    monkeypatch.setattr(split_csv, "parse_url_csv", broken)
    split_csv.handler(s3_event("uploads/h/b1.csv"), None)
    assert "not a readable CSV" in store.get_batch_item("b1")["error"]
