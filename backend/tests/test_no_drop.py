# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json

import boto3
from backend_testkit import OWNER_A, api_event, put_batch_for_tests, utcnow
from botocore.exceptions import ClientError
from test_run_scan import FakeAgentCore, seed

from phish_backend.api import app
from phish_backend.common import clients, scans, store
from phish_backend.worker import dead_letter, run_scan
from phish_contracts.disclaimer import DISCLAIMER_TEXT


def test_transient_failure_retries_then_fails_with_reason(aws):
    err = ClientError(
        {"Error": {"Code": "InternalServerException", "Message": "x"}}, "InvokeHarness"
    )
    fake = FakeAgentCore(error=err)
    msg = seed()
    for attempt in (1, 2):
        try:
            run_scan.process_message(msg, agentcore=fake)
        except run_scan.RetryableScanError as exc:
            assert exc.delay_seconds == 30 * attempt
        else:
            raise AssertionError("attempt should have been retried")
        assert store.get_scan("s1").status == "PENDING"
    run_scan.process_message(msg, agentcore=fake)
    failed = store.get_scan("s1")
    assert failed.status == "FAILED" and failed.attempts == 3
    assert "after 3 attempts" in failed.error and "Correlation ID" in failed.error
    assert fake.invocations == 3


def test_empty_output_is_retried_like_an_error(aws):
    msg = seed()
    try:
        run_scan.process_message(msg, agentcore=FakeAgentCore(text=""))
    except run_scan.RetryableScanError:
        pass
    assert store.get_scan("s1").status == "PENDING"


def test_handler_backs_off_with_visibility_timeout(aws, monkeypatch):
    changed = {}

    class Sqs:
        def change_message_visibility(self, **kw):
            changed.update(kw)

    def boom(message, agentcore=None):
        raise run_scan.RetryableScanError("harness unavailable", delay_seconds=60)

    monkeypatch.setattr(run_scan, "process_message", boom)

    def fake_sqs():
        return Sqs()

    fake_sqs.cache_clear = lambda: None  # clients.reset() clears every cached client
    monkeypatch.setattr(run_scan.clients, "sqs", fake_sqs)
    out = run_scan.handler(
        {"Records": [{"messageId": "m1", "receiptHandle": "rh", "body": "{}"}]}, None
    )
    assert out == {"batchItemFailures": [{"itemIdentifier": "m1"}]}
    assert changed["VisibilityTimeout"] == 60 and changed["ReceiptHandle"] == "rh"


def test_dead_letter_marks_scan_failed_with_reason(aws):
    msg = seed()
    dead_letter.handler({"Records": [{"messageId": "d1", "body": json.dumps(msg)}]}, None)
    failed = store.get_scan("s1")
    assert failed.status == "FAILED" and "Retry" in failed.error


def test_dead_letter_leaves_finished_scans_alone(aws):
    msg = seed()
    run_scan.process_message(msg, agentcore=FakeAgentCore())
    dead_letter.handler({"Records": [{"messageId": "d1", "body": json.dumps(msg)}]}, None)
    assert store.get_scan("s1").status == "COMPLETE"


def call(event):
    response = app.handler(event, None)
    return response["statusCode"], json.loads(response["body"])


def test_retry_endpoint_requeues_only_failed_scans_of_the_owner(aws):
    msg = seed()
    status, _ = call(api_event("POST", "/scans/{id}/retry", path={"id": "s1"}))
    assert status == 409
    store.fail_scan("s1", None, error="boom", completed_at=utcnow())
    assert call(api_event("POST", "/scans/{id}/retry", path={"id": "s1"}, sub="user-b"))[0] == 404
    status, body = call(api_event("POST", "/scans/{id}/retry", path={"id": "s1"}))
    assert status == 202 and body == {
        "scan_id": "s1",
        "status": "PENDING",
        "disclaimer": DISCLAIMER_TEXT,
    }
    again = store.get_scan("s1")
    assert again.status == "PENDING" and again.attempts == 0 and again.error is None
    queued = boto3.client("sqs", region_name="us-west-2").receive_message(
        QueueUrl=aws["queue_url"], MaxNumberOfMessages=10
    )["Messages"]
    assert sum(json.loads(m["Body"])["scan_id"] == "s1" for m in queued) >= 1
    assert msg["scan_id"] == "s1"


def test_batch_retry_failed_requeues_every_failed_scan(aws):
    records = [
        scans.new_scan(OWNER_A, f"https://e{i}.example/", batch_id="b1", scan_id=f"b1-{i}")
        for i in range(3)
    ]
    scans.create_and_enqueue(records)
    for r in records[:2]:
        store.fail_scan(r.scan_id, None, error="boom", completed_at=utcnow())
    put_batch_for_tests("b1", OWNER_A, total=3)
    status, body = call(api_event("POST", "/batches/{id}/retry-failed", path={"id": "b1"}))
    assert status == 202 and body == {"batch_id": "b1", "retried": 2, "disclaimer": DISCLAIMER_TEXT}
    assert {store.get_scan(r.scan_id).status for r in records} == {"PENDING"}


class StreamReplay:
    """Feed moto's real DynamoDB stream for the scans table into the aggregator."""

    def __init__(self):
        self.streams = boto3.client("dynamodbstreams", region_name="us-west-2")
        arn = boto3.client("dynamodb", region_name="us-west-2").describe_table(
            TableName="phish-scans"
        )["Table"]["LatestStreamArn"]
        shard = self.streams.describe_stream(StreamArn=arn)["StreamDescription"]["Shards"][0]
        self.iterator = self.streams.get_shard_iterator(
            StreamArn=arn, ShardId=shard["ShardId"], ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]

    def drain(self):
        from phish_backend.stats import aggregate

        out = self.streams.get_records(ShardIterator=self.iterator)
        self.iterator = out["NextShardIterator"]
        assert aggregate.handler({"Records": out["Records"]}, None) == {"batchItemFailures": []}


def test_retried_batch_closes_with_total_equal_complete_plus_failed(aws):
    replay = StreamReplay()
    put_batch_for_tests("b1", OWNER_A, total=2)
    msgs = []
    for i in range(2):
        msg = seed(f"b1-{i}")
        msgs.append({**msg, "batch_id": "b1"})
    # seed() wrote rows without a batch id; attach them so the batch GSI and counters apply.
    table = boto3.resource("dynamodb", region_name="us-west-2").Table("phish-scans")
    for m in msgs:
        table.update_item(
            Key={"scan_id": m["scan_id"]},
            UpdateExpression="SET batch_id = :b",
            ExpressionAttributeValues={":b": "b1"},
        )
    run_scan.process_message(msgs[0], agentcore=FakeAgentCore())
    bad = FakeAgentCore(text="")
    for _ in range(run_scan.MAX_SCAN_ATTEMPTS):
        try:
            run_scan.process_message(msgs[1], agentcore=bad)
        except run_scan.RetryableScanError:
            pass
    replay.drain()
    closed = store.get_batch("b1")
    assert closed.completed_at is not None
    assert (closed.status_counts["COMPLETE"], closed.status_counts["FAILED"]) == (1, 1)

    assert (
        call(api_event("POST", "/batches/{id}/retry-failed", path={"id": "b1"}))[1]["retried"] == 1
    )
    replay.drain()
    reopened = store.get_batch("b1")
    assert reopened.completed_at is None and reopened.status_counts["FAILED"] == 0

    run_scan.process_message(msgs[1], agentcore=FakeAgentCore())
    replay.drain()
    final = store.get_batch("b1")
    assert final.completed_at is not None
    assert final.total == final.status_counts["COMPLETE"] + final.status_counts["FAILED"] == 2
    assert final.status_counts["RUNNING"] == 0
    stats_all = (
        boto3.resource("dynamodb", region_name="us-west-2")
        .Table("phish-stats")
        .get_item(Key={"owner": OWNER_A, "bucket": "all"})["Item"]
    )
    assert (stats_all["scanned"], stats_all["failed"], stats_all["verdict#phishing"]) == (2, 0, 2)


def test_throttle_without_time_left_releases_without_spending_an_attempt(aws, monkeypatch):
    from phish_backend.common import aws_retry

    def deferred(call, *, what, sleep=None):
        raise aws_retry.ThrottleDeferred(what)

    monkeypatch.setattr(run_scan.aws_retry, "invoke_with_throttle_retry", deferred)
    msg = seed()
    for _ in range(run_scan.MAX_SCAN_ATTEMPTS + 1):
        try:
            run_scan.process_message(msg, agentcore=FakeAgentCore())
        except run_scan.RetryableScanError as exc:
            assert exc.delay_seconds > 0
        else:
            raise AssertionError("a deferred throttle must go back to SQS")
    again = store.get_scan("s1")
    assert again.status == "PENDING" and again.attempts == 0


def test_user_retry_clears_the_previous_claim_evidence(aws):
    msg = seed()
    bad = FakeAgentCore(text="")
    for _ in range(run_scan.MAX_SCAN_ATTEMPTS):
        try:
            run_scan.process_message(msg, agentcore=bad)
        except run_scan.RetryableScanError:
            pass
    assert store.get_scan("s1").started_at is not None
    reopened = store.reopen_failed_scan("s1", OWNER_A)
    # The aggregator reads started_at as "this claim was counted RUNNING".
    assert reopened.started_at is None and reopened.queue_wait_ms is None


def test_user_retry_clears_findings_calls_and_cost_on_the_row(aws):
    msg = seed()
    bad = FakeAgentCore(text="")
    for _ in range(run_scan.MAX_SCAN_ATTEMPTS):
        try:
            run_scan.process_message(msg, agentcore=bad)
        except run_scan.RetryableScanError:
            pass
    failed = store.get_scan("s1")
    assert failed.status == "FAILED" and failed.findings and failed.calls
    reopened = store.reopen_failed_scan("s1", OWNER_A)
    assert reopened.findings == [] and reopened.calls == [] and reopened.cost_usd == 0


def test_submit_with_sqs_down_is_503_and_the_scan_failed(aws, monkeypatch):
    from backend_testkit import FailingSqs, patch_sqs

    sqs = FailingSqs(raise_error=True)
    patch_sqs(monkeypatch, sqs)
    status, body = call(api_event("POST", "/scan", body={"url": "https://a.example/"}))
    assert status == 503
    assert body["error"] == "the scan could not be queued; try again"
    assert sqs.sent == 2  # the first send and one retry
    items, _ = store.scans_for_owner(OWNER_A, 10, None)
    assert [(s.status, s.error) for s in items] == [
        ("FAILED", "the scan could not be queued (send failed twice)")
    ]
    assert items[0].completed_at is not None


def test_submit_queued_on_the_retry_is_202(aws, monkeypatch):
    from backend_testkit import patch_sqs

    real = clients.sqs()

    class FailsOnce:
        sent = 0

        def send_message_batch(self, QueueUrl, Entries):  # noqa: N803 - boto3 names
            self.sent += 1
            if self.sent == 1:
                return {
                    "Failed": [{"Id": e["Id"], "Code": "x", "SenderFault": False} for e in Entries]
                }
            return real.send_message_batch(QueueUrl=QueueUrl, Entries=Entries)

    patch_sqs(monkeypatch, FailsOnce())
    status, body = call(api_event("POST", "/scan", body={"url": "https://a.example/"}))
    assert status == 202 and body["status"] == "PENDING"
    assert store.get_scan(body["scan_id"]).status == "PENDING"


def test_a_send_reported_failed_that_reached_a_worker_is_202(aws, monkeypatch):
    from backend_testkit import FailingSqs, patch_sqs

    class DeliveredAnyway(FailingSqs):
        """Reports failure, but the worker already claimed the scan (RUNNING)."""

        def send_message_batch(self, QueueUrl, Entries):  # noqa: N803 - boto3 names
            for entry in Entries:
                store.claim_scan(json.loads(entry["MessageBody"])["scan_id"], "t", utcnow())
            return super().send_message_batch(QueueUrl, Entries)

    patch_sqs(monkeypatch, DeliveredAnyway())
    status, body = call(api_event("POST", "/scan", body={"url": "https://a.example/"}))
    assert status == 202
    assert store.get_scan(body["scan_id"]).status == "RUNNING"


def test_batches_with_sqs_down_are_accepted_and_left_for_the_sweeper(aws, monkeypatch):
    from backend_testkit import FailingSqs, patch_sqs

    patch_sqs(monkeypatch, FailingSqs(raise_error=True))
    status, body = call(api_event("POST", "/batches", body={"urls": ["https://b.example/"]}))
    assert status == 202
    items, _ = store.scans_for_batch(body["batch_id"], 10, None)
    assert [s.status for s in items] == ["PENDING"]


def _failed_with_findings():
    msg = seed()
    bad = FakeAgentCore(text="")
    for _ in range(run_scan.MAX_SCAN_ATTEMPTS):
        try:
            run_scan.process_message(msg, agentcore=bad)
        except run_scan.RetryableScanError:
            pass
    return store.get_scan("s1")


def test_retry_with_sqs_down_restores_the_failed_scan(aws, monkeypatch):
    from backend_testkit import FailingSqs, patch_sqs

    before = _failed_with_findings()
    patch_sqs(monkeypatch, FailingSqs())
    status, body = call(api_event("POST", "/scans/{id}/retry", path={"id": "s1"}))
    assert status == 503 and "try again" in body["error"]
    after = store.get_scan("s1")
    assert after.status == "FAILED" and after.error == before.error
    assert after.completed_at == before.completed_at and after.total_ms == before.total_ms
    assert len(after.findings) == len(before.findings) and len(after.calls) == len(before.calls)


def test_batch_retry_with_sqs_down_restores_every_scan(aws, monkeypatch):
    from backend_testkit import FailingSqs, patch_sqs

    records = [
        scans.new_scan(OWNER_A, f"https://e{i}.example/", batch_id="b1", scan_id=f"b1-{i}")
        for i in range(2)
    ]
    scans.create_and_enqueue(records)
    for r in records:
        store.fail_scan(r.scan_id, None, error=f"boom {r.scan_id}", completed_at=utcnow())
    put_batch_for_tests("b1", OWNER_A, total=2)
    patch_sqs(monkeypatch, FailingSqs())
    status, body = call(api_event("POST", "/batches/{id}/retry-failed", path={"id": "b1"}))
    assert status == 503
    for r in records:
        again = store.get_scan(r.scan_id)
        assert again.status == "FAILED" and again.error == f"boom {r.scan_id}"
