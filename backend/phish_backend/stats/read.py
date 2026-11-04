# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Build the Insights stats object and the CSV export for one owner."""

import csv
import io
import math
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from phish_backend.common import clients, store
from phish_backend.common.config import settings
from phish_backend.common.timeutil import utcnow
from phish_backend.stats.updates import LAT_BUCKETS, reportable, scan_usages
from phish_contracts.disclaimer import DISCLAIMER_TEXT
from phish_contracts.models import VerdictLabel, defang

RANGES = ("24h", "7d", "30d", "all")
_VERDICTS = [v.value for v in VerdictLabel]
EXPORT_COLUMNS = [
    "scan_id",
    "batch_id",
    "url_defanged",
    "status",
    "verdict",
    "risk_score",
    "queued_at",
    "completed_at",
    "total_ms",
    "input_tokens",
    "output_tokens",
    "cost_usd",
    # Last column, repeated on every row: the file stays plain CSV for any parser, and the
    # notice survives filtering, sorting and copying rows into other sheets.
    "disclaimer",
]
_RANGE_DAYS = {"7d": 7, "30d": 30, "all": 30}


def bucket_keys(range_: str, now: datetime) -> list[tuple[str, str]]:
    if range_ == "24h":
        hours = [now - timedelta(hours=i) for i in range(23, -1, -1)]
        return [(f"{h:%Y-%m-%dT%H}", f"hour#{h:%Y-%m-%dT%H}") for h in hours]
    if range_ == "all":
        return [("all", "all")]
    days = [now - timedelta(days=i) for i in range(_RANGE_DAYS[range_] - 1, -1, -1)]
    return [(f"{d:%Y-%m-%d}", f"day#{d:%Y-%m-%d}") for d in days]


def _load(owner: str, buckets: list[str]) -> dict[str, dict]:
    table = settings().stats_table
    ddb = clients.dynamodb()
    found: dict[str, dict] = {}
    for start in range(0, len(buckets), 100):
        request = {
            table: {"Keys": [{"owner": owner, "bucket": b} for b in buckets[start : start + 100]]}
        }
        while request:
            response = ddb.batch_get_item(RequestItems=request)
            for item in response.get("Responses", {}).get(table, []):
                found[item["bucket"]] = item
            request = response.get("UnprocessedKeys") or None
    return found


def _money(value: Any) -> str:
    return f"{Decimal(str(value or 0)):.4f}"


def _p95(histogram: dict[int, int]) -> int:
    total = sum(histogram.values())
    if not total:
        return 0
    target = math.ceil(total * 0.95)
    running = 0
    for upper in sorted(histogram):
        running += histogram[upper]
        if running >= target:
            return upper
    return max(histogram)


def _p95_report(histogram: dict[int, int], count: int, sum_ms: int) -> tuple[int, bool, bool]:
    """(p95 ms to show, over the top bucket, value is only an upper bound).

    Counters keep latency buckets, not durations, so p95 is normally a bucket edge
    and the UI must present it as a bound. One sample has an exact duration (its
    sum), and no p95 can exceed the summed time of all samples.
    """
    if count == 1 and sum_ms > 0:
        return sum_ms, False, False
    p95_ms, over = reportable(_p95(histogram))
    if over:
        return p95_ms, True, True
    if sum_ms > 0:
        p95_ms = min(p95_ms, sum_ms)
    return p95_ms, False, p95_ms > 0


def _sum(items: list[dict]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for item in items:
        for key, value in item.items():
            if isinstance(value, Decimal | int) and not isinstance(value, bool):
                merged[key] = merged.get(key, 0) + value
    return merged


def _series_point(label: str, item: dict) -> dict:
    point = {"day": label, **{v: int(item.get(f"verdict#{v}", 0)) for v in _VERDICTS}}
    point.update(
        failed=int(item.get("failed", 0)),
        cost_usd=_money(item.get("cost_usd")),
        input_tokens=int(item.get("input_tokens", 0)),
        output_tokens=int(item.get("output_tokens", 0)),
    )
    return point


def build_stats(owner: str, range_: str, now: datetime | None = None) -> dict:
    now = now or utcnow()
    keys = bucket_keys(range_, now)
    series_keys = keys if range_ != "all" else bucket_keys("30d", now)
    loaded = _load(owner, sorted({b for _, b in keys} | {b for _, b in series_keys}))
    totals_src = _sum([loaded[b] for _, b in keys if b in loaded])
    histogram = {
        u: int(totals_src.get(f"lat#{u}", 0)) for u in LAT_BUCKETS if totals_src.get(f"lat#{u}")
    }
    timed = int(totals_src.get("timed", 0))
    p95_ms, p95_over, p95_bound = _p95_report(histogram, timed, int(totals_src.get("sum_ms", 0)))
    totals = {
        "scanned": int(totals_src.get("scanned", 0)),
        **{v: int(totals_src.get(f"verdict#{v}", 0)) for v in _VERDICTS},
        "failed": int(totals_src.get("failed", 0)),
        "cost_usd": _money(totals_src.get("cost_usd")),
        # Scans whose cost_usd leaves out a model with no price: cost_usd is then a lower bound.
        "unpriced_scans": int(totals_src.get("unpriced_scans", 0)),
        "input_tokens": int(totals_src.get("input_tokens", 0)),
        "output_tokens": int(totals_src.get("output_tokens", 0)),
        "avg_ms": int(totals_src.get("sum_ms", 0)) // timed if timed else 0,
        "p95_ms": p95_ms,
        "p95_over_max": p95_over,
        "p95_bound": p95_bound,
    }
    models: dict[str, dict] = {}
    calls: dict[tuple[str, str], dict] = {}
    for key, value in totals_src.items():
        parts = key.split("#")
        if parts[0] == "model" and len(parts) == 3:
            entry = models.setdefault(
                parts[1],
                {
                    "model_id": parts[1],
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cost_usd": Decimal(0),
                    "unpriced": 0,
                },
            )
            field = {
                "in": "input_tokens",
                "out": "output_tokens",
                "cost": "cost_usd",
                "unpriced": "unpriced",
            }[parts[2]]
            entry[field] += value
        elif parts[0] == "call" and len(parts) in (4, 5):
            entry = calls.setdefault((parts[1], parts[2]), {"hist": {}})
            if len(parts) == 5 and parts[3] == "lat":
                entry["hist"][int(parts[4])] = int(value)
            elif len(parts) == 4:
                entry[parts[3]] = int(value)
    by_model = [
        {
            "model_id": m["model_id"],
            "input_tokens": int(m["input_tokens"]),
            "output_tokens": int(m["output_tokens"]),
            "cost_usd": _money(m["cost_usd"]),
            # False when some of this model's calls had no price: cost_usd leaves them out.
            "cost_known": not m["unpriced"],
        }
        for m in sorted(models.values(), key=lambda m: m["model_id"])
    ]
    agentcore = []
    for (kind, name), c in sorted(calls.items()):
        count = c.get("count", 0)
        call_p95, call_over, call_bound = _p95_report(c["hist"], count, c.get("sum_ms", 0))
        agentcore.append(
            {
                "kind": kind,
                "name": name,
                "count": count,
                "avg_ms": c.get("sum_ms", 0) // count if count else 0,
                "p95_ms": call_p95,
                "p95_over_max": call_over,
                "p95_bound": call_bound,
                "errors": c.get("errors", 0),
                "blocked": c.get("blocked", 0),
            }
        )
    recent, _ = store.batches_for_owner(owner, 10, None)
    return {
        "range": range_,
        "totals": totals,
        "daily": [_series_point(label, loaded.get(b, {})) for label, b in series_keys],
        "latency_histogram": [{"upper_ms": u, "count": histogram.get(u, 0)} for u in LAT_BUCKETS],
        "by_model": by_model,
        "agentcore": agentcore,
        "recent_batches": [b.model_dump(mode="json", exclude={"owner"}) for b in recent],
    }


def _safe_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    # Spreadsheet formula injection guard for cells a user can influence.
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def export_csv(owner: str, range_: str, now: datetime | None = None, max_rows: int = 10000) -> str:
    now = now or utcnow()
    since = (
        None
        if range_ == "all"
        else now - (timedelta(hours=24) if range_ == "24h" else timedelta(days=_RANGE_DAYS[range_]))
    )
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(EXPORT_COLUMNS)
    for count, scan in enumerate(store.iter_scans_for_owner(owner, since)):
        if count >= max_rows:
            break
        usages = scan_usages(scan)
        writer.writerow(
            [
                _safe_cell(v)
                for v in (
                    scan.scan_id,
                    scan.batch_id,
                    defang(scan.url),
                    scan.status.value,
                    scan.verdict.verdict.value if scan.verdict else "",
                    scan.verdict.risk_score if scan.verdict else "",
                    scan.queued_at.isoformat(),
                    scan.completed_at.isoformat() if scan.completed_at else "",
                    scan.total_ms,
                    sum(u.input_tokens for u in usages),
                    sum(u.output_tokens for u in usages),
                    scan.cost_usd,
                    DISCLAIMER_TEXT,
                )
            ]
        )
    return out.getvalue()
