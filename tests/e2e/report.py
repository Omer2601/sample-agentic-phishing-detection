# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Latency, failure and cost summary for an end-to-end run."""

import json
import statistics
import time
from collections import Counter, defaultdict
from decimal import Decimal
from pathlib import Path

REPORTS = Path(__file__).parent / "reports"


def _pct(values: list[int], q: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))]


def summarize(label: str, scans: list[dict], wall_clock_ms: int | None) -> dict:
    done = [s for s in scans if s.get("total_ms") is not None]
    times = [int(s["total_ms"]) for s in done]
    calls = defaultdict(list)
    for scan in scans:
        for call in scan.get("calls") or []:
            calls[f"{call['kind']}:{call['name']}"].append(int(call["duration_ms"]))
    return {
        "label": label,
        "submitted": len(scans),
        "status": dict(Counter(s["status"] for s in scans)),
        "verdicts": dict(Counter((s.get("verdict") or {}).get("verdict", "none") for s in scans)),
        "failures": dict(
            Counter(s.get("error", "")[:80] for s in scans if s["status"] == "FAILED")
        ),
        "p50_ms": _pct(times, 0.5),
        "p95_ms": _pct(times, 0.95),
        "mean_ms": int(statistics.mean(times)) if times else 0,
        "wall_clock_ms": wall_clock_ms,
        "cost_usd": str(sum((Decimal(str(s.get("cost_usd", "0"))) for s in scans), Decimal(0))),
        "calls": {
            k: {"count": len(v), "p50_ms": _pct(v, 0.5), "p95_ms": _pct(v, 0.95)}
            for k, v in sorted(calls.items())
        },
    }


def write(summary: dict) -> Path:
    REPORTS.mkdir(exist_ok=True)
    stem = REPORTS / f"{time.strftime('%Y%m%dT%H%M%S')}-{summary['label']}"
    stem.with_suffix(".json").write_text(json.dumps(summary, indent=2))
    lines = [f"# {summary['label']}", "", "| metric | value |", "|---|---|"]
    for key in (
        "submitted",
        "status",
        "verdicts",
        "p50_ms",
        "p95_ms",
        "mean_ms",
        "wall_clock_ms",
        "cost_usd",
    ):
        lines.append(f"| {key} | {summary[key]} |")
    lines += ["", "| call | count | p50 ms | p95 ms |", "|---|---|---|---|"]
    lines += [
        f"| {k} | {v['count']} | {v['p50_ms']} | {v['p95_ms']} |"
        for k, v in summary["calls"].items()
    ]
    if summary["failures"]:
        lines += [
            "",
            "## Failures",
            *[f"- {n} x {reason}" for reason, n in summary["failures"].items()],
        ]
    stem.with_suffix(".md").write_text("\n".join(lines) + "\n")
    return stem.with_suffix(".md")
