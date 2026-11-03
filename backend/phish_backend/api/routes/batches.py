# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""POST /batches, GET /batches, GET /batches/{id}."""

import hashlib
import logging
import math
import uuid

from phish_backend.api.http import ApiError, Request, json_response, public_dump, scan_dump
from phish_backend.api.routes.history import SUMMARY_EXCLUDE
from phish_backend.batch.csv_parse import MAX_UPLOAD_BYTES
from phish_backend.common import clients, guardrails, scans, store
from phish_backend.common.config import settings
from phish_backend.common.timeutil import utcnow
from phish_backend.common.url_input import InvalidUrl, validate_submitted_url
from phish_backend.stats.updates import LAT_BUCKETS, reportable
from phish_contracts.models import BatchRecord, BatchSource

logger = logging.getLogger(__name__)
UPLOAD_SECONDS = 900


def _percentile(item: dict, fraction: float) -> int:
    counts = [(u, int(item.get(f"lat#{u}", 0))) for u in LAT_BUCKETS]
    total = sum(c for _, c in counts)
    if not total:
        return 0
    running = 0
    for upper, count in counts:
        running += count
        if running >= total * fraction:
            return upper
    return LAT_BUCKETS[-1]


def _latency_report(item: dict, page: list, whole_batch: bool) -> dict:
    """p50 and p95 per URL for the batch detail tiles.

    The batch counters keep latency buckets, not durations, so a counter percentile is
    a bucket upper edge (a 41 s median reads 60 s) and is flagged as a bound, as on
    Insights. When this response holds every timed scan of the batch, the scans' own
    total_ms gives exact nearest-rank values instead, and one timed scan is exact from
    sum_scan_ms whatever the page.
    """
    timed = sum(int(item.get(f"lat#{u}", 0)) for u in LAT_BUCKETS)
    durations = sorted(s.total_ms for s in page if s.total_ms is not None)
    report: dict = {}
    for name, fraction in (("p50", 0.5), ("p95", 0.95)):
        if timed and whole_batch and len(durations) == timed:
            value, over, bound = durations[max(0, math.ceil(fraction * timed) - 1)], False, False
        elif timed == 1 and int(item.get("sum_scan_ms", 0)) > 0:
            value, over, bound = int(item["sum_scan_ms"]), False, False
        else:
            value, over = reportable(_percentile(item, fraction))
            bound = value > 0
        report |= {f"{name}_ms": value, f"{name}_over_max": over, f"{name}_bound": bound}
    return report


def create(req: Request) -> dict:
    body = req.json()
    cfg = settings()
    batch_id = str(uuid.uuid4())
    now = utcnow()
    if "urls" in body:
        urls = body["urls"]
        if not isinstance(urls, list) or not urls:
            raise ApiError(400, "urls must be a non-empty list")
        if len(urls) > cfg.json_batch_max:
            raise ApiError(
                400,
                f"at most {cfg.json_batch_max} urls per JSON batch; "
                "upload a CSV for larger batches",
            )
        clean, errors = [], []
        for index, raw in enumerate(urls):
            try:
                url = validate_submitted_url(raw)
            except InvalidUrl as exc:
                errors.append(f"urls[{index}]: {exc}")
                continue
            if url not in clean:
                clean.append(url)
        if errors:
            raise ApiError(400, "; ".join(errors[:10]))
        store.put_batch(
            BatchRecord(
                batch_id=batch_id,
                owner=req.owner,
                source=BatchSource.API,
                total=len(clean),
                created_at=now,
            ),
            awaiting_upload=False,
        )
        records = [
            scans.new_scan(req.owner, u, batch_id=batch_id, now=now, guardrail_events=events)
            for u, events in zip(clean, guardrails.screen_urls(clean), strict=True)
        ]
        try:
            scans.create_and_enqueue(records)
        except scans.EnqueueError:
            # Rows are PENDING without enqueued_at; worker.requeue_stuck queues them.
            logger.warning("batch %s saved but not fully queued; left for the sweep", batch_id)
        store.mark_batch_split(batch_id, now)
        return json_response(202, {"batch_id": batch_id})
    if body.get("upload") is not True:
        raise ApiError(400, "send either urls or upload: true")
    source = body.get("source", "api")
    if source not in ("ui", "api"):
        raise ApiError(400, "source must be ui or api")
    cap = cfg.ui_batch_max if source == "ui" else cfg.api_batch_max
    count = body.get("count")
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= cap:
        raise ApiError(400, f"count must be between 1 and {cap} for {source} uploads")
    store.put_batch(
        BatchRecord(
            batch_id=batch_id,
            owner=req.owner,
            source=BatchSource(source),
            total=count,
            created_at=now,
        ),
        awaiting_upload=True,
    )
    key = f"uploads/{hashlib.sha256(req.owner.encode()).hexdigest()[:16]}/{batch_id}.csv"
    fields = {
        "Content-Type": "text/csv",
        "x-amz-meta-batch-id": batch_id,
        "x-amz-meta-owner": req.owner,
        "x-amz-meta-source": source,
    }
    conditions = [{k: v} for k, v in fields.items()] + [
        ["content-length-range", 1, MAX_UPLOAD_BYTES]
    ]
    post = clients.s3().generate_presigned_post(
        Bucket=cfg.upload_bucket,
        Key=key,
        Fields=fields,
        Conditions=conditions,
        ExpiresIn=UPLOAD_SECONDS,
    )
    return json_response(
        202, {"batch_id": batch_id, "upload_url": post["url"], "upload_fields": post["fields"]}
    )


def list_batches(req: Request) -> dict:
    items, nxt = store.batches_for_owner(req.owner, req.limit(), req.query.get("next"))
    return json_response(200, {"items": [public_dump(b) for b in items], "next": nxt})


def get(req: Request) -> dict:
    batch_id = req.path_id()
    item = store.get_batch_item(batch_id)
    if not item or item.get("owner") != req.owner:
        raise ApiError(404, "batch not found")
    scans_page, nxt = store.scans_for_batch(
        batch_id, req.limit(default=50, maximum=200), req.query.get("next")
    )
    first_page = req.query.get("next") is None
    latency = _latency_report(item, scans_page, whole_batch=first_page and nxt is None)
    return json_response(
        200,
        {
            "batch": public_dump(store.batch_from_item(item)),
            "invalid_rows": store.from_dynamo(item.get("invalid_rows", [])),
            "error": item.get("error"),
            **latency,
            "items": [scan_dump(s, SUMMARY_EXCLUDE) for s in scans_page],
            "next": nxt,
        },
    )
