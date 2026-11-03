# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""DynamoDB access for scans and batches. The only module that knows item shapes.

Counters on batch items are written by stats.aggregate from the scans stream, never
by the worker, so a retried worker cannot double count.
"""

import base64
import binascii
import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

from boto3.dynamodb.conditions import Key
from botocore.exceptions import BotoCoreError, ClientError

from phish_backend.common import clients
from phish_backend.common.config import settings
from phish_backend.common.url_key import dedup_key
from phish_contracts.models import (
    BatchRecord,
    Call,
    Finding,
    ReportStatus,
    ScanRecord,
    ScanStatus,
    Verdict,
    VerdictLabel,
)

logger = logging.getLogger(__name__)

# Longer than the worker Lambda timeout (300 s), so a live attempt is never reclaimed.
CLAIM_LEASE_SECONDS = 360
TERMINAL = {ScanStatus.COMPLETE.value, ScanStatus.FAILED.value}
_COUNTED = (ScanStatus.RUNNING, ScanStatus.COMPLETE, ScanStatus.FAILED)


class ScanMissing(Exception):
    """The scan row does not exist."""


class ClaimUnavailable(Exception):
    """The claim could not be evaluated; the caller must retry the message."""


class BadCursor(ValueError):
    """A pagination token was malformed or belongs to another owner or batch."""


def to_dynamo(value: Any) -> Any:
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: to_dynamo(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [to_dynamo(v) for v in value]
    return value


def from_dynamo(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, dict):
        return {k: from_dynamo(v) for k, v in value.items()}
    if isinstance(value, list):
        return [from_dynamo(v) for v in value]
    return value


def encode_cursor(key: dict | None) -> str | None:
    if not key:
        return None
    return base64.urlsafe_b64encode(json.dumps(from_dynamo(key)).encode()).decode()


def decode_cursor(token: str | None, *, field: str, expected: str) -> dict | None:
    """Decode a cursor and prove it was issued for this owner (or batch)."""
    if not token:
        return None
    try:
        key = json.loads(base64.urlsafe_b64decode(token.encode()))
    except (ValueError, binascii.Error) as exc:
        raise BadCursor("invalid cursor") from exc
    if not isinstance(key, dict) or not all(isinstance(v, str | int) for v in key.values()):
        raise BadCursor("invalid cursor")
    if key.get(field) != expected:
        raise BadCursor("invalid cursor")
    return to_dynamo(key)


def _scans():
    return clients.dynamodb().Table(settings().scans_table)


def _batches():
    return clients.dynamodb().Table(settings().batches_table)


def _code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _dump(model) -> Any:
    return to_dynamo(model.model_dump(mode="json", exclude_none=True))


def _scan_from_item(item: dict) -> ScanRecord:
    return ScanRecord.model_validate(from_dynamo(item))


# ---- scans ---------------------------------------------------------------------


def expires_at(start: datetime) -> int:
    """Epoch seconds for the DynamoDB TTL attribute: start + RETENTION_DAYS (default 90)."""
    return int((start + timedelta(days=settings().retention_days)).timestamp())


def put_scan_if_absent(record: ScanRecord) -> bool:
    item = _dump(record)
    item["expires_at"] = expires_at(record.queued_at)
    # Written on every row, dedup on or off, so GET /scans/lookup and a later switch-on of
    # POST /scan dedup need no backfill. Internal: never on the wire model.
    item["dedup_key"] = dedup_key(record.owner, record.url)
    try:
        _scans().put_item(Item=item, ConditionExpression="attribute_not_exists(scan_id)")
    except ClientError as exc:
        if _code(exc) == "ConditionalCheckFailedException":
            return False
        raise
    return True


def mark_enqueued(scan_id: str, now: datetime | None = None) -> None:
    """Stamp enqueued_at (epoch seconds) after a successful SQS send of a PENDING row."""
    stamp = int((now or datetime.now(tz=UTC)).timestamp())
    try:
        _scans().update_item(
            Key={"scan_id": scan_id},
            UpdateExpression="SET enqueued_at = :now",
            ConditionExpression="#s = :pending",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":now": stamp, ":pending": ScanStatus.PENDING.value},
        )
    except ClientError as exc:
        if _code(exc) == "ConditionalCheckFailedException":
            return  # already claimed by a worker: the stamp is no longer needed
        # The message was sent; without the stamp the sweeper sends one duplicate, which
        # the worker's claim discards. Not worth failing the request over.
        logger.warning("could not stamp enqueued_at on %s (%s)", scan_id, _code(exc))
    except BotoCoreError as exc:
        logger.warning("could not stamp enqueued_at on %s (%s)", scan_id, type(exc).__name__)


def get_scan(scan_id: str, *, consistent: bool = False) -> ScanRecord | None:
    item = _scans().get_item(Key={"scan_id": scan_id}, ConsistentRead=consistent).get("Item")
    return _scan_from_item(item) if item else None


# Sparse GSI: pk dedup_key, sk queued_at, INCLUDE [status, completed_at]. Rows written before
# the key existed are simply never matched.
DEDUP_INDEX = "dedup-queued_at"


def iter_scans_by_dedup_key(key: str, page_size: int, max_pages: int) -> Iterator[dict]:
    """Newest-first index entries (scan_id, status, queued_at, completed_at) for a key.

    Pages lazily, so a caller that stops at the first match reads one page. The index is
    eventually consistent: callers re-read the row before acting on an entry.
    """
    kwargs: dict[str, Any] = {
        "IndexName": DEDUP_INDEX,
        "KeyConditionExpression": Key("dedup_key").eq(key),
        "ScanIndexForward": False,
        "Limit": page_size,
    }
    for _ in range(max_pages):
        response = _scans().query(**kwargs)
        for item in response.get("Items", []):
            yield from_dynamo(item)
        last = response.get("LastEvaluatedKey")
        if not last:
            return
        kwargs["ExclusiveStartKey"] = last


def memory_matches(scan_id: str) -> list[dict]:
    """The episodic memory matches the worker recorded for a scan (internal attribute)."""
    item = (
        _scans()
        .get_item(
            Key={"scan_id": scan_id},
            ProjectionExpression="memory_matches",
        )
        .get("Item")
    )
    matches = (item or {}).get("memory_matches") or []
    return [m for m in matches if isinstance(m, dict)]


def scan_owners(scan_ids: list[str]) -> dict[str, str]:
    """Owner of each existing scan id; ids with no row are absent."""
    owners: dict[str, str] = {}
    for scan_id in dict.fromkeys(scan_ids):
        item = (
            _scans()
            .get_item(
                Key={"scan_id": scan_id},
                ProjectionExpression="#o",
                ExpressionAttributeNames={"#o": "owner"},
            )
            .get("Item")
        )
        if item and item.get("owner"):
            owners[scan_id] = str(item["owner"])
    return owners


def claim_scan(scan_id: str, token: str, now: datetime) -> ScanRecord | None:
    """Move PENDING (or a stale RUNNING) to RUNNING for exactly one attempt.

    Returns None for a duplicate message (already running or finished).
    """
    claimed = claim_attempt(scan_id, token, now)
    return claimed[0] if claimed else None


def claim_attempt(scan_id: str, token: str, now: datetime) -> tuple[ScanRecord, int] | None:
    """claim_scan plus the claim number: 1, 2, 3 ... over the scan's whole life.

    Unlike attempts, the claim number is never reset by a user retry, so it names a
    fresh harness session for every run of the scan.
    """
    try:
        item = _scans().get_item(Key={"scan_id": scan_id}, ConsistentRead=True).get("Item")
    except ClientError as exc:
        raise ClaimUnavailable(str(exc)) from exc
    if not item:
        raise ScanMissing(scan_id)
    if item["status"] in TERMINAL:
        return None
    now_epoch = int(now.timestamp())
    if (
        item["status"] == ScanStatus.RUNNING.value
        and int(item.get("claimed_at", 0)) >= now_epoch - CLAIM_LEASE_SECONDS
    ):
        return None
    queued = datetime.fromisoformat(item["queued_at"])
    wait_ms = max(0, int((now - queued).total_seconds() * 1000))
    try:
        response = _scans().update_item(
            Key={"scan_id": scan_id},
            UpdateExpression=(
                "SET #s = :running, started_at = :started, queue_wait_ms = :wait, "
                "claim_token = :token, claimed_at = :now ADD attempts :one, claims :one"
            ),
            ConditionExpression="#s = :pending OR (#s = :running AND claimed_at < :stale)",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":running": ScanStatus.RUNNING.value,
                ":pending": ScanStatus.PENDING.value,
                ":started": now.isoformat().replace("+00:00", "Z"),
                ":wait": wait_ms,
                ":token": token,
                ":now": now_epoch,
                ":stale": now_epoch - CLAIM_LEASE_SECONDS,
                ":one": 1,
            },
            ReturnValues="ALL_NEW",
        )
    except ClientError as exc:
        if _code(exc) == "ConditionalCheckFailedException":
            return None
        raise ClaimUnavailable(str(exc)) from exc
    attributes = response["Attributes"]
    return _scan_from_item(attributes), int(attributes.get("claims", 1))


def _finish(scan_id: str, token: str | None, sets: dict[str, Any]) -> bool:
    names: dict[str, str] = {}
    values: dict[str, Any] = {}
    parts = []
    for i, (attr, value) in enumerate(sets.items()):
        names[f"#a{i}"] = attr
        values[f":v{i}"] = value
        parts.append(f"#a{i} = :v{i}")
    if token:
        condition = "claim_token = :token"
        values[":token"] = token
    else:
        # Only this branch references #s; DynamoDB rejects unused attribute names.
        names["#s"] = "status"
        condition = "attribute_exists(scan_id) AND NOT (#s IN (:complete, :failed))"
        values[":complete"] = ScanStatus.COMPLETE.value
        values[":failed"] = ScanStatus.FAILED.value
    try:
        _scans().update_item(
            Key={"scan_id": scan_id},
            UpdateExpression="SET " + ", ".join(parts) + " REMOVE claim_token",
            ConditionExpression=condition,
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )
    except ClientError as exc:
        if _code(exc) == "ConditionalCheckFailedException":
            logger.warning(
                "scan %s was finished by another attempt; this result is discarded", scan_id
            )
            return False
        raise
    return True


def complete_scan(
    scan_id: str,
    token: str,
    *,
    verdict: Verdict,
    findings: list[Finding],
    calls: list[Call],
    cost: Decimal,
    completed_at: datetime,
    total_ms: int,
    memory_matches: list[dict[str, str | None]] | None = None,
    report_status: ReportStatus = ReportStatus.READY,
    unpriced_models: list[str] | None = None,
) -> bool:
    """Store the verdict and finish the scan (COMPLETE means: the verdict is available).

    report_status PENDING keeps a lease (report_token, report_claimed_at) so only this
    worker writes the report; a redelivered message can take over only after it expires.
    """
    report_fields: dict[str, Any] = {"report_status": report_status.value}
    stamp = completed_at.isoformat().replace("+00:00", "Z")
    if report_status == ReportStatus.PENDING:
        report_fields.update(
            report_started_at=stamp,
            report_token=token,
            report_claimed_at=int(completed_at.timestamp()),
        )
    else:
        report_fields.update(report_started_at=stamp, report_ready_at=stamp)
    return _finish(
        scan_id,
        token,
        {
            **report_fields,
            "status": ScanStatus.COMPLETE.value,
            # Deployment-wide, so possibly other owners' scan ids: internal only, never on the
            # wire model. routes/scans.py filters it to the requester's own scans.
            "memory_matches": list(memory_matches or []),
            "verdict": _dump(verdict),
            "findings": [_dump(f) for f in findings],
            "calls": [_dump(c) for c in calls],
            "cost_usd": str(cost),
            "unpriced_models": list(unpriced_models or []),
            "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
            "total_ms": total_ms,
        },
    )


def claim_report(scan_id: str, token: str, now: datetime) -> ScanRecord | None:
    """Take the report lease of a COMPLETE scan whose report is PENDING and unclaimed.

    None when the scan has no pending report or another worker holds a live lease.
    """
    epoch = int(now.timestamp())
    try:
        response = _scans().update_item(
            Key={"scan_id": scan_id},
            UpdateExpression="SET report_token = :t, report_claimed_at = :now",
            ConditionExpression=(
                "#s = :complete AND report_status = :pending AND "
                "(attribute_not_exists(report_claimed_at) OR report_claimed_at < :stale)"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":t": token,
                ":now": epoch,
                ":complete": ScanStatus.COMPLETE.value,
                ":pending": ReportStatus.PENDING.value,
                ":stale": epoch - CLAIM_LEASE_SECONDS,
            },
            ReturnValues="ALL_NEW",
        )
    except ClientError as exc:
        if _code(exc) == "ConditionalCheckFailedException":
            return None
        raise
    return _scan_from_item(response["Attributes"])


def finish_report(
    scan_id: str,
    token: str,
    *,
    report_status: ReportStatus,
    ready_at: datetime,
    report_markdown: str | None = None,
    error: str | None = None,
    calls: list[Call] | None = None,
    cost: Decimal | None = None,
    unpriced_models: list[str] | None = None,
) -> bool:
    """Write the outcome of turn 2. False when the lease was lost; the result is discarded.

    The verdict is never touched except for its report_markdown. calls and cost are the
    new totals (turn-1 values plus the turn-2 call).
    """
    names = {"#rs": "report_status", "#ra": "report_ready_at"}
    values: dict[str, Any] = {
        ":rs": report_status.value,
        ":ra": ready_at.isoformat().replace("+00:00", "Z"),
        ":token": token,
        ":pending": ReportStatus.PENDING.value,
    }
    sets = ["#rs = :rs", "#ra = :ra"]
    if report_markdown is not None:
        names.update({"#v": "verdict", "#rm": "report_markdown"})
        values[":rm"] = report_markdown
        sets.append("#v.#rm = :rm")
    if error is not None:
        names["#re"] = "report_error"
        values[":re"] = error[:300]
        sets.append("#re = :re")
    if calls is not None:
        names["#c"] = "calls"
        values[":calls"] = [_dump(c) for c in calls]
        sets.append("#c = :calls")
    if cost is not None:
        names["#cost"] = "cost_usd"
        values[":cost"] = str(cost)
        sets.append("#cost = :cost")
        names["#up"] = "unpriced_models"
        values[":up"] = list(unpriced_models or [])
        sets.append("#up = :up")
    try:
        _scans().update_item(
            Key={"scan_id": scan_id},
            UpdateExpression="SET " + ", ".join(sets) + " REMOVE report_token",
            ConditionExpression="report_token = :token AND report_status = :pending",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )
    except ClientError as exc:
        if _code(exc) == "ConditionalCheckFailedException":
            logger.warning("scan %s report was finished by another worker; discarded", scan_id)
            return False
        raise
    return True


def fail_scan(
    scan_id: str,
    token: str | None,
    *,
    error: str,
    completed_at: datetime,
    total_ms: int | None = None,
    findings: list[Finding] | None = None,
    calls: list[Call] | None = None,
) -> bool:
    sets: dict[str, Any] = {
        "status": ScanStatus.FAILED.value,
        "error": error[:500],
        "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
    }
    if total_ms is not None:
        sets["total_ms"] = total_ms
    if findings:
        sets["findings"] = [_dump(f) for f in findings]
    if calls:
        sets["calls"] = [_dump(c) for c in calls]
    return _finish(scan_id, token, sets)


def fail_pending_scan(scan_id: str, *, error: str, completed_at: datetime) -> bool:
    """PENDING to FAILED, for a scan whose message could not be queued.

    False when the row is no longer PENDING (a send reported as failed reached a worker).
    """
    try:
        _scans().update_item(
            Key={"scan_id": scan_id},
            UpdateExpression="SET #s = :failed, #e = :error, completed_at = :done",
            ConditionExpression="attribute_exists(scan_id) AND #s = :pending",
            ExpressionAttributeNames={"#s": "status", "#e": "error"},
            ExpressionAttributeValues={
                ":failed": ScanStatus.FAILED.value,
                ":pending": ScanStatus.PENDING.value,
                ":error": error[:500],
                ":done": completed_at.isoformat().replace("+00:00", "Z"),
            },
        )
    except ClientError as exc:
        if _code(exc) == "ConditionalCheckFailedException":
            return False
        raise
    return True


def add_guardrail_events(scan_id: str, events: list[str]) -> None:
    _scans().update_item(
        Key={"scan_id": scan_id},
        UpdateExpression=(
            "SET guardrail_events = list_append(if_not_exists(guardrail_events, :empty), :e)"
        ),
        ExpressionAttributeValues={":e": events, ":empty": []},
    )


def _page(
    table, index: str, key_name: str, key_value: str, limit: int, cursor: str | None, field: str
) -> tuple[list[dict], str | None]:
    kwargs: dict[str, Any] = {
        "IndexName": index,
        "KeyConditionExpression": Key(key_name).eq(key_value),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    start = decode_cursor(cursor, field=field, expected=key_value)
    if start:
        kwargs["ExclusiveStartKey"] = start
    response = table.query(**kwargs)
    return response.get("Items", []), encode_cursor(response.get("LastEvaluatedKey"))


def scans_for_owner(
    owner: str, limit: int, cursor: str | None
) -> tuple[list[ScanRecord], str | None]:
    items, nxt = _page(_scans(), "owner-queued_at", "owner", owner, limit, cursor, "owner")
    return [_scan_from_item(i) for i in items], nxt


def scans_for_batch(
    batch_id: str, limit: int, cursor: str | None
) -> tuple[list[ScanRecord], str | None]:
    items, nxt = _page(_scans(), "batch-queued_at", "batch_id", batch_id, limit, cursor, "batch_id")
    return [_scan_from_item(i) for i in items], nxt


def iter_scans_for_owner(owner: str, since: datetime | None) -> Iterator[ScanRecord]:
    condition = Key("owner").eq(owner)
    if since is not None:
        condition = condition & Key("queued_at").gte(since.isoformat().replace("+00:00", "Z"))
    kwargs: dict[str, Any] = {
        "IndexName": "owner-queued_at",
        "KeyConditionExpression": condition,
        "ScanIndexForward": False,
    }
    while True:
        response = _scans().query(**kwargs)
        for item in response.get("Items", []):
            yield _scan_from_item(item)
        if "LastEvaluatedKey" not in response:
            return
        kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]


# ---- batches -------------------------------------------------------------------


def put_batch(record: BatchRecord, *, awaiting_upload: bool) -> None:
    item = _dump(record.model_copy(update={"status_counts": {}, "verdict_counts": {}}))
    item.pop("status_counts", None)
    item.pop("verdict_counts", None)
    # Lifecycle attributes are owned by the conditional updates below: the split
    # and the sweeper test attribute_exists / attribute_not_exists on them, so a
    # dumped awaiting_upload=False, or any split_at or error, must not be written.
    for field in ("awaiting_upload", "split_at", "error"):
        item.pop(field, None)
    item["cost_usd"] = Decimal(str(record.cost_usd))
    for status in _COUNTED:
        item[f"status#{status.value}"] = record.status_counts.get(status, 0)
    for label in VerdictLabel:
        item[f"verdict#{label.value}"] = record.verdict_counts.get(label, 0)
    if awaiting_upload:
        item["awaiting_upload"] = True
    item["expires_at"] = expires_at(record.created_at)
    _batches().put_item(Item=item, ConditionExpression="attribute_not_exists(batch_id)")


def get_batch_item(batch_id: str) -> dict | None:
    return _batches().get_item(Key={"batch_id": batch_id}, ConsistentRead=True).get("Item")


def batch_from_item(item: dict) -> BatchRecord:
    data = from_dynamo(item)
    counts = {s: int(data.get(f"status#{s.value}", 0)) for s in _COUNTED}
    counts[ScanStatus.PENDING] = max(0, int(data.get("total", 0)) - sum(counts.values()))
    verdicts = {v: int(data.get(f"verdict#{v.value}", 0)) for v in VerdictLabel}
    data["status_counts"] = counts
    data["verdict_counts"] = verdicts
    data["cost_usd"] = str(item.get("cost_usd", "0"))
    return BatchRecord.model_validate(data)


def get_batch(batch_id: str) -> BatchRecord | None:
    item = get_batch_item(batch_id)
    return batch_from_item(item) if item else None


def batches_for_owner(
    owner: str, limit: int, cursor: str | None
) -> tuple[list[BatchRecord], str | None]:
    items, nxt = _page(_batches(), "owner-created_at", "owner", owner, limit, cursor, "owner")
    return [batch_from_item(i) for i in items], nxt


def set_batch_total(batch_id: str, total: int, invalid_rows: list[dict]) -> None:
    _batches().update_item(
        Key={"batch_id": batch_id},
        UpdateExpression="SET #t = :t, invalid_rows = :inv REMOVE awaiting_upload",
        ExpressionAttributeNames={"#t": "total"},
        ExpressionAttributeValues={":t": total, ":inv": invalid_rows[:100]},
    )


def mark_batch_split(batch_id: str, now: datetime) -> bool:
    try:
        _batches().update_item(
            Key={"batch_id": batch_id},
            UpdateExpression="SET split_at = :now",
            ConditionExpression="attribute_not_exists(split_at)",
            ExpressionAttributeValues={":now": now.isoformat().replace("+00:00", "Z")},
        )
    except ClientError as exc:
        if _code(exc) == "ConditionalCheckFailedException":
            return False
        raise
    return True


def mark_batch_error(
    batch_id: str, message: str, now: datetime, *, only_if_awaiting_upload: bool = False
) -> bool:
    """Close a batch as failed with a reason. False when the condition did not hold."""
    stamp = now.isoformat().replace("+00:00", "Z")
    kwargs: dict[str, Any] = {}
    if only_if_awaiting_upload:
        kwargs["ConditionExpression"] = (
            "attribute_exists(awaiting_upload) AND attribute_not_exists(split_at)"
        )
    try:
        _batches().update_item(
            Key={"batch_id": batch_id},
            UpdateExpression=(
                "SET #e = :e, #t = :zero, completed_at = :now, split_at = :now, "
                "wall_clock_ms = :zero REMOVE awaiting_upload"
            ),
            ExpressionAttributeNames={"#e": "error", "#t": "total"},
            ExpressionAttributeValues={":e": message[:500], ":zero": 0, ":now": stamp},
            **kwargs,
        )
    except ClientError as exc:
        if _code(exc) == "ConditionalCheckFailedException":
            return False
        raise
    return True


def _scan_all(table, **kwargs: Any) -> Iterator[dict]:
    while True:
        response = table.scan(**kwargs)
        yield from response.get("Items", [])
        if "LastEvaluatedKey" not in response:
            return
        kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]


PENDING_INDEX = "status-queued_at"
# DynamoDB refuses reads from a GSI until it is ACTIVE ("Cannot read from backfilling global
# secondary index"). On the first deploy with the index, a big table backfills for a while.
_INDEX_NOT_READY = ("backfilling", "being created")


def index_not_ready(exc: ClientError) -> bool:
    """True for the ValidationException DynamoDB gives while a GSI is created or backfilled."""
    message = str(exc.response.get("Error", {}).get("Message", "")).lower()
    return _code(exc) == "ValidationException" and any(m in message for m in _INDEX_NOT_READY)


def index_unavailable(exc: ClientError) -> bool:
    """True when a GSI cannot be read yet: it does not exist, or is being created or backfilled."""
    message = str(exc.response.get("Error", {}).get("Message", "")).lower()
    return index_not_ready(exc) or (
        _code(exc) == "ValidationException" and "specified index" in message
    )


def pending_scan_items() -> Iterator[dict]:
    """Every PENDING scan row, for worker.requeue_stuck, oldest first.

    A Query on the status index, so the sweep reads only scans in flight, never the whole
    table. The index projects scan_id, status, queued_at, owner, url, batch_id,
    enqueued_at and retried_at: enough to rebuild the SQS message and judge staleness.
    """
    kwargs: dict[str, Any] = {
        "IndexName": PENDING_INDEX,
        "KeyConditionExpression": "#s = :pending",
        "ExpressionAttributeNames": {"#s": "status"},
        "ExpressionAttributeValues": {":pending": ScanStatus.PENDING.value},
    }
    while True:
        response = _scans().query(**kwargs)
        yield from response.get("Items", [])
        if "LastEvaluatedKey" not in response:
            return
        kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]


def awaiting_upload_batch_ids(created_before: datetime) -> list[str]:
    """Upload batches still waiting for their CSV that were created before the cutoff."""
    return [
        item["batch_id"]
        for item in _scan_all(
            _batches(),
            FilterExpression="attribute_exists(awaiting_upload) AND created_at < :cutoff",
            ExpressionAttributeValues={
                ":cutoff": created_before.isoformat().replace("+00:00", "Z")
            },
            ProjectionExpression="batch_id",
        )
    ]


def release_scan(scan_id: str, token: str, *, error: str, refund_attempt: bool = False) -> bool:
    """Hand a claimed scan back to PENDING so the next SQS delivery retries it.

    refund_attempt undoes the claim's attempt count, for a release where nothing ran.
    """
    expression = "SET #s = :pending, last_error = :e REMOVE claim_token, claimed_at"
    values: dict[str, Any] = {
        ":pending": ScanStatus.PENDING.value,
        ":e": error[:500],
        ":token": token,
    }
    if refund_attempt:
        expression = (
            "SET #s = :pending, last_error = :e, attempts = attempts - :one "
            "REMOVE claim_token, claimed_at"
        )
        values[":one"] = 1
    try:
        _scans().update_item(
            Key={"scan_id": scan_id},
            UpdateExpression=expression,
            ConditionExpression="claim_token = :token",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues=values,
        )
    except ClientError as exc:
        if _code(exc) == "ConditionalCheckFailedException":
            return False
        raise
    return True


def retry_stamp() -> str:
    return datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")


def reopen_failed_scan(
    scan_id: str, owner: str, retried_at: str | None = None
) -> ScanRecord | None:
    """FAILED to PENDING for a user retry. None when the scan is not FAILED or not this owner's.

    retried_at (default now) identifies this reopen for revert_reopen and the aggregator.
    """
    try:
        response = _scans().update_item(
            Key={"scan_id": scan_id},
            UpdateExpression=(
                "SET #s = :pending, attempts = :zero, retried_at = :now "
                "REMOVE #e, completed_at, total_ms, claim_token, claimed_at, "
                "started_at, queue_wait_ms, findings, calls, cost_usd, unpriced_models, enqueued_at"
            ),
            ConditionExpression="#s = :failed AND #o = :owner",
            ExpressionAttributeNames={"#s": "status", "#e": "error", "#o": "owner"},
            ExpressionAttributeValues={
                ":pending": ScanStatus.PENDING.value,
                ":failed": ScanStatus.FAILED.value,
                ":owner": owner,
                ":zero": 0,
                ":now": retried_at or retry_stamp(),
            },
            ReturnValues="ALL_NEW",
        )
    except ClientError as exc:
        if _code(exc) == "ConditionalCheckFailedException":
            return None
        raise
    return _scan_from_item(response["Attributes"])


_RESTORED_ON_REVERT = (
    "error",
    "completed_at",
    "total_ms",
    "findings",
    "calls",
    "cost_usd",
    "unpriced_models",
    "started_at",
    "queue_wait_ms",
    "attempts",
)


def revert_reopen(prior: ScanRecord, retried_at: str) -> bool:
    """Undo reopen_failed_scan when the retry message could not be queued.

    Conditional on the row still being that reopen, unclaimed: back to FAILED with the
    prior reason, findings, calls and cost, so the aggregator re-adds exactly the
    counters its reopen reversal removed.
    """
    dumped = _dump(prior)
    sets = {k: dumped[k] for k in _RESTORED_ON_REVERT if k in dumped}
    sets["status"] = ScanStatus.FAILED.value
    names = {f"#a{i}": k for i, k in enumerate(sets)}
    values: dict[str, Any] = {f":v{i}": v for i, v in enumerate(sets.values())}
    values.update({":pending": ScanStatus.PENDING.value, ":r": retried_at})
    names["#st"] = "status"
    try:
        _scans().update_item(
            Key={"scan_id": prior.scan_id},
            UpdateExpression="SET " + ", ".join(f"#a{i} = :v{i}" for i in range(len(sets))),
            ConditionExpression=(
                "#st = :pending AND retried_at = :r AND attribute_not_exists(claim_token)"
            ),
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )
    except ClientError as exc:
        if _code(exc) == "ConditionalCheckFailedException":
            return False
        raise
    return True


def failed_scans_for_batch(batch_id: str) -> list[ScanRecord]:
    out: list[ScanRecord] = []
    cursor = None
    while True:
        page, cursor = scans_for_batch(batch_id, 200, cursor)
        out += [s for s in page if s.status == ScanStatus.FAILED]
        if not cursor:
            return out
