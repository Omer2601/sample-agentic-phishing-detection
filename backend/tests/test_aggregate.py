# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
from datetime import UTC, datetime
from decimal import Decimal

from backend_testkit import OWNER_A
from boto3.dynamodb.types import TypeSerializer

from phish_backend.common import store
from phish_backend.stats import aggregate
from phish_backend.stats.updates import lat_bucket
from phish_contracts.models import BatchRecord, BatchSource

SER = TypeSerializer()
T0 = "2026-09-29T12:00:00Z"


def image(d):
    return {k: SER.serialize(store.to_dynamo(v)) for k, v in d.items()}


def scan_item(status, **extra):
    base = {
        "scan_id": "s1",
        "owner": OWNER_A,
        "url": "https://x.example/",
        "status": status,
        "queued_at": T0,
        "batch_id": "b1",
    }
    base.update(extra)
    return base


COMPLETE = scan_item(
    "COMPLETE",
    started_at=T0,
    completed_at="2026-09-29T12:00:35Z",
    total_ms=35000,
    cost_usd="0.150000",
    verdict={
        "verdict": "phishing",
        "risk_score": 95,
        "confidence": "high",
        "action": "block",
        "summary": "s",
        "report_markdown": "r",
    },
    findings=[
        {
            "agent": "url_analyst",
            "status": "ok",
            "verdict": "phishing",
            "confidence": 90,
            "usage": {
                "input_tokens": 100,
                "output_tokens": 10,
                "model_id": "global.anthropic.claude-sonnet-5-5",
            },
            "latency_ms": 5000,
            "calls": [],
        }
    ],
    calls=[
        {
            "kind": "harness",
            "name": "orchestrator",
            "started_at": T0,
            "duration_ms": 30000,
            "status": "ok",
            "usage": {
                "input_tokens": 1000,
                "output_tokens": 200,
                "model_id": "us.anthropic.claude-opus-5-5",
            },
        },
        {
            "kind": "browser",
            "name": "brand_visual",
            "started_at": T0,
            "duration_ms": 9000,
            "status": "ok",
        },
        {
            "kind": "model",
            "name": "brand_visual",
            "started_at": T0,
            "duration_ms": 4000,
            "status": "blocked_by_guardrail",
            "usage": {
                "input_tokens": 999,
                "output_tokens": 999,
                "model_id": "global.anthropic.claude-sonnet-5-5",
            },
        },
    ],
)


def record(old, new, seq="1"):
    return {
        "eventName": "MODIFY",
        "dynamodb": {"SequenceNumber": seq, "OldImage": image(old), "NewImage": image(new)},
    }


def seed_batch(total=1):
    store.put_batch(
        BatchRecord(
            batch_id="b1",
            owner=OWNER_A,
            source=BatchSource.API,
            total=total,
            created_at=datetime(2026, 9, 29, 11, 59, 50, tzinfo=UTC),
        ),
        awaiting_upload=False,
    )


def stats(bucket):
    import boto3

    return (
        boto3.resource("dynamodb", region_name="us-west-2")
        .Table("phish-stats")
        .get_item(Key={"owner": OWNER_A, "bucket": bucket})
        .get("Item", {})
    )


def test_lat_bucket():
    assert lat_bucket(35000) == 40000
    assert lat_bucket(10**10) == 999999999


def test_running_then_complete_updates_batch_and_stats(aws):
    seed_batch()
    aggregate.apply_record(record(scan_item("PENDING"), scan_item("RUNNING", started_at=T0)))
    assert store.get_batch("b1").status_counts["RUNNING"] == 1
    aggregate.apply_record(record(scan_item("RUNNING", started_at=T0), COMPLETE))
    batch = store.get_batch("b1")
    assert batch.status_counts["RUNNING"] == 0
    assert batch.status_counts["COMPLETE"] == 1
    assert batch.verdict_counts["phishing"] == 1
    assert batch.completed_at is not None and batch.wall_clock_ms == 45000
    for bucket in ("all", "day#2026-09-29", "hour#2026-09-29T12"):
        item = stats(bucket)
        assert item["scanned"] == 1 and item["verdict#phishing"] == 1
        assert item["input_tokens"] == 1100 and item["output_tokens"] == 210
        assert item["lat#40000"] == 1
        assert item["call#browser#brand_visual#count"] == 1
        assert item["call#model#brand_visual#blocked"] == 1
        assert item["model#us.anthropic.claude-opus-5-5#in"] == 1000
        assert item["cost_usd"] == Decimal("0.150000")
    assert "expires_at" in stats("hour#2026-09-29T12")


def test_stream_retry_is_idempotent(aws):
    seed_batch()
    rec = record(scan_item("RUNNING", started_at=T0), COMPLETE)
    aggregate.apply_record(rec)
    aggregate.apply_record(rec)
    assert stats("all")["scanned"] == 1
    assert store.get_batch("b1").status_counts["COMPLETE"] == 1


def test_failed_counts_as_failed(aws):
    seed_batch()
    aggregate.apply_record(
        record(
            scan_item("RUNNING"),
            scan_item("FAILED", completed_at="2026-09-29T12:01:00Z", error="x", total_ms=60000),
        )
    )
    assert stats("all")["failed"] == 1
    assert store.get_batch("b1").status_counts["FAILED"] == 1


def test_no_transition_is_ignored(aws):
    aggregate.apply_record(record(scan_item("RUNNING"), scan_item("RUNNING")))
    assert stats("all") == {}


def test_handler_reports_failed_sequence(aws, monkeypatch):
    def boom(rec):
        raise RuntimeError("x")

    monkeypatch.setattr(aggregate, "apply_record", boom)
    out = aggregate.handler(
        {"Records": [record(scan_item("PENDING"), scan_item("RUNNING"), seq="42")]}, None
    )
    assert out == {"batchItemFailures": [{"itemIdentifier": "42"}]}


def aggregate_image(item: dict) -> dict:
    ser = TypeSerializer()
    return {k: ser.serialize(v) for k, v in item.items() if v is not None}


def test_retry_reverses_failed_counts_once(aws):
    old = {
        "scan_id": "r1",
        "owner": OWNER_A,
        "url": "https://x.example/",
        "batch_id": None,
        "status": "FAILED",
        "queued_at": "2026-09-29T12:00:00Z",
        "completed_at": "2026-09-29T12:01:00Z",
        "error": "boom",
    }
    new = {**old, "status": "PENDING"}
    aggregate._terminal(aggregate.ScanRecord.model_validate(old), was_running=False)
    rec = {
        "eventName": "MODIFY",
        "dynamodb": {
            "OldImage": aggregate_image(old),
            "NewImage": aggregate_image(new),
            "SequenceNumber": "1",
        },
    }
    aggregate.apply_record(rec)
    aggregate.apply_record(rec)  # stream retry: must not subtract twice
    assert stats("all")["failed"] == 0 and stats("all")["scanned"] == 0


def test_released_then_dead_lettered_scan_leaves_no_phantom_running(aws):
    # Claimed (RUNNING counted), released to PENDING by a transient failure, then failed
    # from PENDING by the DLQ sweeper: the RUNNING count must still go back to zero.
    seed_batch()
    aggregate.apply_record(record(scan_item("PENDING"), scan_item("RUNNING", attempts=1)))
    aggregate.apply_record(
        record(scan_item("RUNNING", attempts=1), scan_item("PENDING", attempts=1))
    )
    aggregate.apply_record(
        record(
            scan_item("PENDING", attempts=1),
            scan_item("FAILED", attempts=1, error="dlq", completed_at="2026-09-29T12:05:00Z"),
        )
    )
    batch = store.get_batch("b1")
    assert batch.status_counts["RUNNING"] == 0 and batch.status_counts["FAILED"] == 1
    assert batch.completed_at is not None


def test_retry_of_an_old_scan_reverses_even_after_markers_expired(aws):
    import boto3

    old = {
        "scan_id": "r2",
        "owner": OWNER_A,
        "url": "https://x.example/",
        "batch_id": None,
        "status": "FAILED",
        "queued_at": "2026-09-29T12:00:00Z",
        "completed_at": "2026-09-29T12:01:00Z",
        "error": "boom",
    }
    aggregate._terminal(aggregate.ScanRecord.model_validate(old), was_running=False)
    # TTL removed the TERMINAL marker long before the user pressed Retry.
    boto3.resource("dynamodb", region_name="us-west-2").Table("phish-stats").delete_item(
        Key={"owner": "marker#r2", "bucket": "TERMINAL"}
    )
    new = {**old, "status": "PENDING", "retried_at": "2026-10-20T09:00:00Z"}
    rec = {
        "eventName": "MODIFY",
        "dynamodb": {
            "OldImage": aggregate_image(old),
            "NewImage": aggregate_image(new),
            "SequenceNumber": "7",
        },
    }
    aggregate.apply_record(rec)
    aggregate.apply_record(rec)
    assert stats("all")["failed"] == 0 and stats("all")["scanned"] == 0


def test_markers_expire_after_eight_days():
    assert aggregate.MARKER_TTL_SECONDS == 8 * 86400


def test_batch_closes_on_stream_retry_after_close_failed(aws, monkeypatch):
    # The TERMINAL transaction committed but closing the batch raised; the stream retry
    # sees the marker and skips the counters, and must still close the batch.
    seed_batch()
    rec = record(scan_item("RUNNING", started_at=T0), COMPLETE)
    real_close = aggregate._maybe_close_batch

    def boom(batch_id, finished):
        raise RuntimeError("throttled")

    monkeypatch.setattr(aggregate, "_maybe_close_batch", boom)
    try:
        aggregate.apply_record(rec)
    except RuntimeError:
        pass
    assert store.get_batch("b1").completed_at is None
    monkeypatch.setattr(aggregate, "_maybe_close_batch", real_close)
    aggregate.apply_record(rec)
    batch = store.get_batch("b1")
    assert batch.completed_at is not None and batch.status_counts["COMPLETE"] == 1


def test_refunded_release_then_dead_letter_leaves_no_phantom_running(aws):
    # A deferred throttle refunds the attempt (attempts back to 0) but the claim already
    # counted RUNNING; started_at is the evidence that it did.
    seed_batch()
    aggregate.apply_record(
        record(scan_item("PENDING"), scan_item("RUNNING", attempts=1, started_at=T0))
    )
    aggregate.apply_record(
        record(
            scan_item("RUNNING", attempts=1, started_at=T0),
            scan_item("PENDING", attempts=0, started_at=T0),
        )
    )
    aggregate.apply_record(
        record(
            scan_item("PENDING", attempts=0, started_at=T0),
            scan_item("FAILED", error="dlq", started_at=T0, completed_at="2026-09-29T12:05:00Z"),
        )
    )
    assert store.get_batch("b1").status_counts["RUNNING"] == 0


def _counters(item):
    skip = {"owner", "bucket", "expires_at", "batch_id", "total", "created_at", "source"}
    return {k: v for k, v in item.items() if k not in skip and isinstance(v, int | Decimal)}


def test_retry_reverses_every_counter_the_failed_attempt_added(aws):
    import boto3

    seed_batch()
    failed = {
        **COMPLETE,
        "status": "FAILED",
        "error": "no verdict",
        "completed_at": "2026-09-29T12:01:00Z",
        "total_ms": 60000,
        "cost_usd": "0.050000",
    }
    failed.pop("verdict")
    aggregate._terminal(aggregate.ScanRecord.model_validate(failed), was_running=False)
    assert stats("all")["call#harness#orchestrator#count"] == 1
    reopened = {**failed, "status": "PENDING", "retried_at": "2026-09-29T13:00:00Z"}
    for key in ("error", "completed_at", "total_ms"):
        reopened.pop(key)
    aggregate.apply_record(record(failed, reopened, seq="9"))
    for bucket in ("all", "day#2026-09-29", "hour#2026-09-29T12"):
        nonzero = {k: v for k, v in _counters(stats(bucket)).items() if v != 0}
        assert nonzero == {}, bucket
    batch = (
        boto3.resource("dynamodb", region_name="us-west-2")
        .Table("phish-batches")
        .get_item(Key={"batch_id": "b1"})["Item"]
    )
    assert {k: v for k, v in _counters(batch).items() if v != 0} == {}
    assert "completed_at" not in batch


def test_error_404_verdict_lands_in_batch_and_stats_counters(aws):
    seed_batch()
    verdict = {**COMPLETE["verdict"], "verdict": "error_404", "risk_score": 10, "action": "allow"}
    done = {**COMPLETE, "verdict": verdict}
    aggregate.apply_record(record(scan_item("RUNNING", started_at=T0), done))
    assert store.get_batch("b1").verdict_counts["error_404"] == 1
    for bucket in ("all", "day#2026-09-29", "hour#2026-09-29T12"):
        item = stats(bucket)
        assert item["verdict#error_404"] == 1 and "verdict#phishing" not in item


def test_stats_update_counts_a_model_with_no_price_instead_of_pricing_it_at_zero():
    from phish_backend.stats.updates import stats_update
    from phish_contracts.models import Call, CallKind, ScanRecord, Usage

    scan = ScanRecord.model_validate(store.from_dynamo(store.to_dynamo(COMPLETE)))
    harness = Call(
        kind=CallKind.HARNESS,
        name="orchestrator",
        started_at=datetime(2026, 9, 29, 12, tzinfo=UTC),
        duration_ms=1000,
        status="ok",
        usage=Usage(input_tokens=10, output_tokens=1, model_id="xx.anthropic.claude-future-9"),
    )
    unpriced = scan.model_copy(
        update={"calls": [harness], "unpriced_models": ["xx.anthropic.claude-future-9"]}
    )
    adds = stats_update(unpriced).adds
    assert adds["model#xx.anthropic.claude-future-9#unpriced"] == 1
    assert adds["unpriced_scans"] == 1
    priced = stats_update(scan).adds
    assert "unpriced_scans" not in priced
    assert not [k for k in priced if k.endswith("#unpriced")]
