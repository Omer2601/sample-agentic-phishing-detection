# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A tiny result cache on DynamoDB for RDAP lookups and web search results.

Off unless PHISH_CACHE_TABLE is set, and then it fails open: any error (throttle, timeout,
missing permission, bad row) is logged at WARNING and treated as a miss. It never raises, so a
cache problem can only cost a live lookup, never a scan.

Rows: pk (S) "rdap#<registered domain>" or "websearch#<brand>", value (S, JSON), fetched_at
(S, ISO), ttl (N, epoch seconds, the table's TTL attribute). DynamoDB deletes expired rows up
to about 48 hours late, so get() checks ttl itself.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import UTC, datetime
from typing import Any

import boto3
from botocore.config import Config

logger = logging.getLogger(__name__)

TABLE_ENV = "PHISH_CACHE_TABLE"
RDAP_TTL_ENV = "PHISH_RDAP_CACHE_TTL_S"
WEBSEARCH_TTL_ENV = "PHISH_WEBSEARCH_CACHE_TTL_S"
DEFAULT_RDAP_TTL_S = 7 * 24 * 3600
# Short so that a poisoned search result cannot stick (docs/security.md).
DEFAULT_WEBSEARCH_TTL_S = 24 * 3600

_SPACES = re.compile(r"\s+")
# One try plus one retry, one second each way: the cache must never cost more than a live call.
_CLIENT_CONFIG = Config(
    connect_timeout=1, read_timeout=1, retries={"total_max_attempts": 2, "mode": "standard"}
)
_client: Any = None


def enabled() -> bool:
    return bool(os.environ.get(TABLE_ENV, "").strip())


def rdap_key(registered_domain: str) -> str:
    return "rdap#" + registered_domain.strip().strip(".").lower()


def websearch_key(brand: str) -> str:
    return "websearch#" + _SPACES.sub(" ", brand or "").strip().lower()


def _ttl_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        seconds = int(raw)
    except ValueError:
        logger.warning("cache ttl ignored: %s is not an integer", name)
        return default
    return seconds if seconds > 0 else default


def rdap_ttl_s() -> int:
    return _ttl_from_env(RDAP_TTL_ENV, DEFAULT_RDAP_TTL_S)


def websearch_ttl_s() -> int:
    return _ttl_from_env(WEBSEARCH_TTL_ENV, DEFAULT_WEBSEARCH_TTL_S)


def _default_client() -> Any:
    global _client
    if _client is None:
        region = os.environ.get("AWS_REGION") or os.environ["AWS_DEFAULT_REGION"]
        _client = boto3.client("dynamodb", region_name=region, config=_CLIENT_CONFIG)
    return _client


def _kind(pk: str) -> str:
    return pk.split("#", 1)[0]


def get(pk: str, *, client: Any = None, now: float | None = None) -> dict | None:
    """The cached value for pk, or None on a miss, an expired row, an error or caching off."""
    table = os.environ.get(TABLE_ENV, "").strip()
    if not table:
        return None
    kind = _kind(pk)
    try:
        item = (
            (client or _default_client())
            .get_item(TableName=table, Key={"pk": {"S": pk}})
            .get("Item")
        )
        value = _decode(item, time.time() if now is None else now)
    except Exception as exc:  # noqa: BLE001 - fail open: any cache problem is a miss
        logger.warning("cache get failed type=%s error=%s", kind, type(exc).__name__)
        return None
    logger.info("cache %s type=%s", "hit" if value is not None else "miss", kind)
    return value


def _decode(item: dict | None, now: float) -> dict | None:
    if not item:
        return None
    if int(item["ttl"]["N"]) <= now:
        return None
    value = json.loads(item["value"]["S"])
    return value if isinstance(value, dict) else None


def put(pk: str, value: dict, ttl_s: int, *, client: Any = None, now: float | None = None) -> bool:
    """Store value for ttl_s seconds. True when written; False on any error or caching off."""
    table = os.environ.get(TABLE_ENV, "").strip()
    if not table or ttl_s <= 0:
        return False
    stamp = time.time() if now is None else now
    try:
        (client or _default_client()).put_item(
            TableName=table,
            Item={
                "pk": {"S": pk},
                "value": {"S": json.dumps(value, separators=(",", ":"))},
                "fetched_at": {"S": datetime.fromtimestamp(stamp, UTC).isoformat()},
                "ttl": {"N": str(int(stamp) + int(ttl_s))},
            },
        )
    except Exception as exc:  # noqa: BLE001 - fail open: a failed write only loses a cache fill
        logger.warning("cache put failed type=%s error=%s", _kind(pk), type(exc).__name__)
        return False
    logger.info("cache store type=%s ttl_s=%d", _kind(pk), ttl_s)
    return True
