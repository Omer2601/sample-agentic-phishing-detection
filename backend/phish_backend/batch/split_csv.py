# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""S3 ObjectCreated handler: turn an uploaded CSV into queued scans."""

import csv
import logging
import uuid
from urllib.parse import unquote_plus

from phish_backend.batch.csv_parse import MAX_UPLOAD_BYTES, UNREADABLE, parse_url_csv
from phish_backend.common import clients, guardrails, log, scans, store
from phish_backend.common.config import settings
from phish_backend.common.timeutil import utcnow

logger = logging.getLogger(__name__)


def handler(event, context) -> None:
    log.configure()
    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = unquote_plus(record["s3"]["object"]["key"])
        process_object(bucket, key)


def process_object(bucket: str, key: str) -> None:
    s3 = clients.s3()
    head = s3.head_object(Bucket=bucket, Key=key)
    meta = head.get("Metadata", {})
    batch_id, owner, source = (
        meta.get("batch-id", ""),
        meta.get("owner", ""),
        meta.get("source", "api"),
    )
    item = store.get_batch_item(batch_id) if batch_id else None
    if not item or item.get("owner") != owner:
        logger.warning("upload %s does not match a batch owned by its uploader; ignored", key)
        return
    if "split_at" in item:
        logger.info("batch %s already split; S3 event retry ignored", batch_id)
        return
    now = utcnow()
    if int(head.get("ContentLength", 0)) > MAX_UPLOAD_BYTES:
        store.mark_batch_error(batch_id, "CSV is larger than 1 MB", now)
        return
    cap = settings().ui_batch_max if source == "ui" else settings().api_batch_max
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read(MAX_UPLOAD_BYTES + 1)
    # A bad file is the uploader's problem, not a transient one: record it on the batch and
    # return, because raising would make S3 re-invoke this handler on the same object.
    try:
        parsed = parse_url_csv(body, cap)
    except UnicodeDecodeError:
        store.mark_batch_error(batch_id, "CSV must be UTF-8 text", now)
        return
    except csv.Error:
        store.mark_batch_error(batch_id, UNREADABLE, now)
        return
    except ValueError as exc:
        store.mark_batch_error(batch_id, str(exc), now)
        return
    if parsed.over_cap:
        store.mark_batch_error(
            batch_id,
            f"CSV has more than {cap} unique URLs; the limit for {source} uploads is {cap}",
            now,
        )
        return
    if not parsed.urls:
        store.mark_batch_error(batch_id, "CSV contains no valid URLs", now)
        return
    records = [
        scans.new_scan(
            owner,
            url,
            batch_id=batch_id,
            scan_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{batch_id}:{i}")),
            now=now,
            guardrail_events=events,
        )
        for i, (url, events) in enumerate(
            zip(parsed.urls, guardrails.screen_urls(parsed.urls), strict=True)
        )
    ]
    # Total first, so the progress denominator is right before any scan finishes.
    store.set_batch_total(batch_id, len(records), parsed.invalid)
    scans.create_and_enqueue(records)
    store.mark_batch_split(batch_id, now)
    logger.info(
        "batch %s split: %d queued, %d invalid, %d duplicates",
        batch_id,
        len(records),
        parsed.invalid_count,
        parsed.duplicates,
    )
