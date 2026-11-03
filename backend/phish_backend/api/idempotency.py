# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Idempotency-Key handling for POST /scan.

A key is scoped to the request's owner (the signed-in user for the web console, the IAM
identity for a direct API caller), so two owners can use the same key and never see each
other's scans. A claim lives for WINDOW_SECONDS; DynamoDB TTL removes it later, and a row
past expires_at is treated as absent because TTL deletion can lag by up to two days.
"""

import re
import time
from dataclasses import dataclass

from botocore.exceptions import ClientError

from phish_backend.common import clients
from phish_backend.common.config import settings

HEADER = "Idempotency-Key"
WINDOW_SECONDS = 24 * 60 * 60
# A claim is written before its scan row. Longer than the API Lambda timeout (30 s): a claim
# this old with no scan row belongs to a request that died, so a retry may take it over.
LEASE_SECONDS = 60
_CLAIM_ATTEMPTS = 3
_KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
INVALID_KEY = f"{HEADER} must be 1-128 characters of letters, digits, '.', '_', ':' or '-'"
# A caller that sends the key relies on it, so a deployment without the table refuses the
# request rather than risk a duplicate scan.
NOT_CONFIGURED = f"{HEADER} is not supported by this deployment; retry without the header"


class InvalidKey(ValueError):
    pass


@dataclass(frozen=True)
class Claim:
    scan_id: str
    url: str
    created_at: int
    # True when the key was claimed for a scan that POST /scan dedup handed back.
    deduplicated: bool = False
    # True only on the Claim that claim() returns to the request whose conditional put won.
    # A request that lost the race gets the holder's claim with won=False and replays it.
    won: bool = False


def configured() -> bool:
    return bool(settings().idempotency_table)


def validate_key(raw: str) -> str:
    value = raw.strip()
    if not _KEY_RE.match(value):
        raise InvalidKey(INVALID_KEY)
    return value


def _table():
    return clients.dynamodb().Table(settings().idempotency_table)


def _pk(owner: str, key: str) -> str:
    return f"{owner}#{key}"


def find(owner: str, key: str, *, now: float | None = None) -> Claim | None:
    item = _table().get_item(Key={"pk": _pk(owner, key)}, ConsistentRead=True).get("Item")
    if not item or int(item.get("expires_at", 0)) <= int(now if now is not None else time.time()):
        return None
    return Claim(
        scan_id=str(item["scan_id"]),
        url=str(item["url"]),
        created_at=int(item["created_at"]),
        deduplicated=bool(item.get("deduplicated", False)),
    )


def claim(
    owner: str,
    key: str,
    scan_id: str,
    url: str,
    *,
    now: float | None = None,
    replace_scan_id: str | None = None,
    deduplicated: bool = False,
) -> Claim:
    """Record key -> scan_id unless a live claim exists; returns the claim that holds the key.

    replace_scan_id takes over a live claim that still names that scan (a stale claim whose
    request died before writing its scan row); a claim naming any other scan is kept.
    """
    stamp = int(now if now is not None else time.time())
    condition = "attribute_not_exists(pk) OR expires_at <= :now"
    values: dict[str, object] = {":now": stamp}
    if replace_scan_id is not None:
        condition += " OR scan_id = :old"
        values[":old"] = replace_scan_id
    for _ in range(_CLAIM_ATTEMPTS):
        try:
            _table().put_item(
                Item={
                    "pk": _pk(owner, key),
                    "scan_id": scan_id,
                    "url": url,
                    "created_at": stamp,
                    "expires_at": stamp + WINDOW_SECONDS,
                    "deduplicated": deduplicated,
                },
                ConditionExpression=condition,
                ExpressionAttributeValues=values,
            )
            return Claim(
                scan_id=scan_id, url=url, created_at=stamp, deduplicated=deduplicated, won=True
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                raise
        held = find(owner, key, now=stamp)
        if held is not None:
            return held
        # The holder released or expired between the put and the read: try the put again.
    raise RuntimeError(f"{HEADER} claim did not settle after {_CLAIM_ATTEMPTS} attempts")


def release(owner: str, key: str, scan_id: str) -> None:
    """Drop this scan's claim so the caller can retry with the same key after a 503."""
    try:
        _table().delete_item(
            Key={"pk": _pk(owner, key)},
            ConditionExpression="scan_id = :s",
            ExpressionAttributeValues={":s": scan_id},
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
            raise
