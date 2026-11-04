# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""DynamoDB stream on `scans`: the single writer of batch counters and Insights stats."""

import logging
import time
from datetime import datetime
from decimal import Decimal

from boto3.dynamodb.types import TypeDeserializer
from botocore.exceptions import ClientError

from phish_backend.common import clients, log, store
from phish_backend.common.config import settings
from phish_backend.common.timeutil import ms_between, utcnow
from phish_backend.stats.updates import Update, lat_bucket, stats_update
from phish_contracts.models import ScanRecord

logger = logging.getLogger(__name__)
_DESER = TypeDeserializer()
HOUR_TTL_SECONDS = 8 * 86400
# interfaces.md: hour buckets and idempotency markers expire after 8 days.
MARKER_TTL_SECONDS = 8 * 86400


def handler(event, context):
    log.configure()
    for rec in event.get("Records", []):
        try:
            apply_record(rec)
        except Exception:  # noqa: BLE001 - reported to Lambda so this and later records are retried in order
            logger.exception(
                "stats aggregation failed for sequence %s", rec["dynamodb"]["SequenceNumber"]
            )
            return {"batchItemFailures": [{"itemIdentifier": rec["dynamodb"]["SequenceNumber"]}]}
    return {"batchItemFailures": []}


def _image(rec: dict, key: str) -> dict:
    raw = rec.get("dynamodb", {}).get(key) or {}
    return store.from_dynamo({k: _DESER.deserialize(v) for k, v in raw.items()})


def apply_record(rec: dict) -> None:
    if rec.get("eventName") not in ("INSERT", "MODIFY"):
        return
    new, old = _image(rec, "NewImage"), _image(rec, "OldImage")
    new_status, old_status = new.get("status"), old.get("status")
    if (
        new_status == old_status == "COMPLETE"
        and old.get("report_status") == "PENDING"
        and new.get("report_status") in ("READY", "FAILED")
    ):
        _report_finished(ScanRecord.model_validate(old), ScanRecord.model_validate(new))
        return
    if not new_status or new_status == old_status:
        return
    if old_status == "FAILED" and new_status == "PENDING":
        # retried_at is unique per user retry; the sequence number covers images without it.
        reopen_id = str(new.get("retried_at") or rec.get("dynamodb", {}).get("SequenceNumber", ""))
        _reopen(ScanRecord.model_validate(old), reopen_id)
        return
    if new_status == "RUNNING":
        _running(new)
    elif new_status in store.TERMINAL and old_status not in store.TERMINAL:
        # A scan released back to PENDING after a claim was already counted as RUNNING by
        # that claim, so finishing from PENDING must still undo that count. started_at is
        # set by every claim and cleared by a user retry; attempts can be refunded to 0.
        was_running = old_status == "RUNNING" or (
            old_status == "PENDING"
            and (int(old.get("attempts") or 0) > 0 or bool(old.get("started_at")))
        )
        _terminal(ScanRecord.model_validate(new), was_running=was_running)


def _running(item: dict) -> None:
    if not item.get("batch_id"):
        return
    u = Update()
    u.add("status#RUNNING", 1)
    u.set_if_absent("first_started_at", item.get("started_at") or item["queued_at"])
    _transact(
        item["scan_id"], "RUNNING", [(settings().batches_table, {"batch_id": item["batch_id"]}, u)]
    )


def _batch_update(scan: ScanRecord) -> Update:
    """Batch counters one finished scan adds (the RUNNING decrement is separate)."""
    b = Update()
    b.add(f"status#{scan.status.value}", 1)
    if scan.verdict is not None:
        b.add(f"verdict#{scan.verdict.verdict.value}", 1)
    b.add("cost_usd", Decimal(str(scan.cost_usd)))
    if scan.total_ms is not None:
        b.add("sum_scan_ms", scan.total_ms)
        b.add(f"lat#{lat_bucket(scan.total_ms)}", 1)
    return b


def _negated(update: Update) -> Update:
    out = Update()
    out.adds = {name: -value for name, value in update.adds.items()}
    return out


def _terminal(scan: ScanRecord, *, was_running: bool) -> None:
    finished = scan.completed_at or utcnow()
    stats = stats_update(scan)
    hour = Update()
    hour.adds = dict(stats.adds)
    hour.set_if_absent("expires_at", int(time.time()) + HOUR_TTL_SECONDS)
    table = settings().stats_table
    writes = [
        (table, {"owner": scan.owner, "bucket": "all"}, stats),
        (table, {"owner": scan.owner, "bucket": f"day#{finished:%Y-%m-%d}"}, stats),
        (table, {"owner": scan.owner, "bucket": f"hour#{finished:%Y-%m-%dT%H}"}, hour),
    ]
    if scan.batch_id:
        b = _batch_update(scan)
        if was_running:
            b.add("status#RUNNING", -1)
        writes.append((settings().batches_table, {"batch_id": scan.batch_id}, b))
    _transact(scan.scan_id, "TERMINAL", writes)
    # Unconditional: a stream retry after the counters committed but the close failed
    # finds the TERMINAL marker, and the batch must still close. The close is idempotent.
    if scan.batch_id:
        _maybe_close_batch(scan.batch_id, finished)


def _report_finished(old: ScanRecord, new: ScanRecord) -> None:
    """The report was written after the verdict was counted: add only what turn 2 added.

    The scan itself (scanned, verdict, latency) was counted when it became COMPLETE. What
    changes now is the cost, tokens and calls of the report turn, found as the difference
    between the stats of the two images, so nothing is counted twice.
    """
    before, after = stats_update(old).adds, stats_update(new).adds
    delta = Update()
    for name, value in after.items():
        diff = value - before.get(name, 0)
        if diff:
            delta.add(name, diff)
    if not delta.adds:
        return
    finished = new.completed_at or utcnow()
    hour = Update()
    hour.adds = dict(delta.adds)
    hour.set_if_absent("expires_at", int(time.time()) + HOUR_TTL_SECONDS)
    table = settings().stats_table
    writes = [
        (table, {"owner": new.owner, "bucket": "all"}, delta),
        (table, {"owner": new.owner, "bucket": f"day#{finished:%Y-%m-%d}"}, delta),
        (table, {"owner": new.owner, "bucket": f"hour#{finished:%Y-%m-%dT%H}"}, hour),
    ]
    if new.batch_id and new.cost_usd != old.cost_usd:
        batch = Update()
        batch.add("cost_usd", Decimal(str(new.cost_usd)) - Decimal(str(old.cost_usd)))
        writes.append((settings().batches_table, {"batch_id": new.batch_id}, batch))
    _transact(new.scan_id, "REPORT", writes)


def _transact(scan_id: str, transition: str, writes: list[tuple[str, dict, Update]]) -> bool:
    items = [
        {
            "Put": {
                "TableName": settings().stats_table,
                "Item": {
                    "owner": f"marker#{scan_id}",
                    "bucket": transition,
                    "expires_at": int(time.time()) + MARKER_TTL_SECONDS,
                },
                "ConditionExpression": "attribute_not_exists(#o)",
                "ExpressionAttributeNames": {"#o": "owner"},
            }
        }
    ]
    for table, key, update in writes:
        expression, names, values = update.render()
        items.append(
            {
                "Update": {
                    "TableName": table,
                    "Key": key,
                    "UpdateExpression": expression,
                    "ExpressionAttributeNames": names,
                    "ExpressionAttributeValues": values,
                }
            }
        )
    try:
        # The resource's client accepts Python types (boto3 injects the serializer).
        clients.dynamodb().meta.client.transact_write_items(TransactItems=items)
    except ClientError as exc:
        reasons = exc.response.get("CancellationReasons") or []
        if (
            exc.response["Error"]["Code"] == "TransactionCanceledException"
            and reasons
            and reasons[0].get("Code") == "ConditionalCheckFailed"
        ):
            logger.info("scan %s %s already aggregated; stream retry ignored", scan_id, transition)
            return False
        raise
    return True


def _reopen(old: ScanRecord, reopen_id: str) -> None:
    """A user retry: undo every counter this scan's FAILED attempt added, once.

    The scan is then counted again when it finishes.
    """
    finished = old.completed_at or utcnow()
    table = settings().stats_table
    marker = f"marker#{old.scan_id}"
    # Idempotency comes from a marker per retry, not from the TERMINAL marker: that one
    # expires after MARKER_TTL_SECONDS while a FAILED scan can be retried for RETENTION_DAYS.
    items: list[dict] = [
        {
            "Put": {
                "TableName": table,
                "Item": {
                    "owner": marker,
                    "bucket": f"REOPEN#{reopen_id}",
                    "expires_at": int(time.time()) + MARKER_TTL_SECONDS,
                },
                "ConditionExpression": "attribute_not_exists(#o)",
                "ExpressionAttributeNames": {"#o": "owner"},
            }
        },
        {"Delete": {"TableName": table, "Key": {"owner": marker, "bucket": "TERMINAL"}}},
        {"Delete": {"TableName": table, "Key": {"owner": marker, "bucket": "RUNNING"}}},
    ]
    # Reverse exactly what _terminal added for the failed attempt: the same stats_update
    # and batch update, negated, so tokens, cost, latency, model and call counters all
    # return to where they were and total == COMPLETE + FAILED holds after the rerun.
    reverse = _negated(stats_update(old))
    hour = _negated(stats_update(old))
    # The hour bucket may have expired already; never recreate it without a TTL.
    hour.set_if_absent("expires_at", int(time.time()) + HOUR_TTL_SECONDS)
    writes = [
        (table, {"owner": old.owner, "bucket": "all"}, reverse),
        (table, {"owner": old.owner, "bucket": f"day#{finished:%Y-%m-%d}"}, reverse),
        (table, {"owner": old.owner, "bucket": f"hour#{finished:%Y-%m-%dT%H}"}, hour),
    ]
    if old.batch_id:
        writes.append(
            (settings().batches_table, {"batch_id": old.batch_id}, _negated(_batch_update(old)))
        )
    for target, key, update in writes:
        expression, names, values = update.render()
        if target == settings().batches_table:
            expression += " REMOVE completed_at, wall_clock_ms"
        items.append(
            {
                "Update": {
                    "TableName": target,
                    "Key": key,
                    "UpdateExpression": expression,
                    "ExpressionAttributeNames": names,
                    "ExpressionAttributeValues": values,
                }
            }
        )
    try:
        clients.dynamodb().meta.client.transact_write_items(TransactItems=items)
    except ClientError as exc:
        reasons = exc.response.get("CancellationReasons") or []
        if (
            exc.response["Error"]["Code"] == "TransactionCanceledException"
            and reasons
            and reasons[0].get("Code") == "ConditionalCheckFailed"
        ):
            logger.info("scan %s reopen already applied; stream retry ignored", old.scan_id)
            return
        raise


def _maybe_close_batch(batch_id: str, finished: datetime) -> None:
    item = store.get_batch_item(batch_id)
    if not item or "completed_at" in item or item.get("awaiting_upload"):
        return
    done = int(item.get("status#COMPLETE", 0)) + int(item.get("status#FAILED", 0))
    total = int(item.get("total", 0))
    if total == 0 or done < total:
        return
    created = datetime.fromisoformat(item["created_at"])
    try:
        clients.dynamodb().Table(settings().batches_table).update_item(
            Key={"batch_id": batch_id},
            UpdateExpression="SET completed_at = :t, wall_clock_ms = :w",
            ConditionExpression="attribute_not_exists(completed_at)",
            ExpressionAttributeValues={
                ":t": finished.isoformat().replace("+00:00", "Z"),
                ":w": ms_between(created, finished),
            },
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise
