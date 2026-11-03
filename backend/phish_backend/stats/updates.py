# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Counter updates derived from one finished scan."""

from decimal import Decimal
from typing import Any

from phish_backend.common import cost
from phish_contracts.models import CallKind, ScanRecord, ScanStatus, Usage

LAT_BUCKETS = (10000, 20000, 30000, 40000, 60000, 90000, 120000, 999999999)
# The last bucket is open-ended; a percentile landing in it is reported as the last
# finite bound plus a p95_over_max flag, never as 999999999 ms.
OPEN_BUCKET = LAT_BUCKETS[-1]
MAX_REPORTED_MS = LAT_BUCKETS[-2]


def reportable(upper_ms: int) -> tuple[int, bool]:
    """(value to show, whether the true value is above MAX_REPORTED_MS)."""
    if upper_ms >= OPEN_BUCKET:
        return MAX_REPORTED_MS, True
    return upper_ms, False


def lat_bucket(ms: int) -> int:
    # The last bucket is open-ended: anything slower still counts in it.
    return next((b for b in LAT_BUCKETS if ms <= b), LAT_BUCKETS[-1])


class Update:
    """Accumulate ADD and SET-if-absent clauses, then render a DynamoDB UpdateExpression."""

    def __init__(self) -> None:
        self.adds: dict[str, Any] = {}
        self.sets: dict[str, Any] = {}

    def add(self, name: str, value: int | Decimal) -> None:
        self.adds[name] = self.adds.get(name, 0) + value

    def set_if_absent(self, name: str, value: Any) -> None:
        self.sets[name] = value

    def render(self) -> tuple[str, dict[str, str], dict[str, Any]]:
        names: dict[str, str] = {}
        values: dict[str, Any] = {}
        set_parts, add_parts = [], []
        for i, (attr, value) in enumerate(self.sets.items()):
            names[f"#s{i}"] = attr
            values[f":s{i}"] = value
            set_parts.append(f"#s{i} = if_not_exists(#s{i}, :s{i})")
        for i, (attr, value) in enumerate(self.adds.items()):
            names[f"#a{i}"] = attr
            values[f":a{i}"] = value
            add_parts.append(f"#a{i} :a{i}")
        expression = []
        if set_parts:
            expression.append("SET " + ", ".join(set_parts))
        if add_parts:
            expression.append("ADD " + ", ".join(add_parts))
        return " ".join(expression), names, values


def scan_usages(scan: ScanRecord) -> list[Usage]:
    # Orchestrator tokens live on the harness call, specialist tokens on each Finding.
    # Nested model calls repeat specialist tokens, so they are timing-only here.
    usages = [c.usage for c in scan.calls if c.kind == CallKind.HARNESS and c.usage]
    usages += [f.usage for f in scan.findings]
    return usages


def stats_update(scan: ScanRecord) -> Update:
    u = Update()
    u.add("scanned", 1)
    if scan.status == ScanStatus.FAILED or scan.verdict is None:
        u.add("failed", 1)
    else:
        u.add(f"verdict#{scan.verdict.verdict.value}", 1)
    for usage in scan_usages(scan):
        u.add("input_tokens", usage.input_tokens)
        u.add("output_tokens", usage.output_tokens)
        u.add(f"model#{usage.model_id}#in", usage.input_tokens)
        u.add(f"model#{usage.model_id}#out", usage.output_tokens)
        priced = cost.price_usage(usage)
        if priced is None:
            # Counted, so the Insights page can say the model's cost is unknown, not $0.
            u.add(f"model#{usage.model_id}#unpriced", 1)
        u.add(f"model#{usage.model_id}#cost", priced or Decimal(0))
    u.add("cost_usd", Decimal(str(scan.cost_usd)))
    if scan.unpriced_models:
        u.add("unpriced_scans", 1)
    if scan.total_ms is not None:
        u.add("sum_ms", scan.total_ms)
        u.add("timed", 1)
        u.add(f"lat#{lat_bucket(scan.total_ms)}", 1)
    for call in scan.calls:
        prefix = f"call#{call.kind.value}#{call.name}"
        u.add(f"{prefix}#count", 1)
        u.add(f"{prefix}#sum_ms", call.duration_ms)
        u.add(f"{prefix}#lat#{lat_bucket(call.duration_ms)}", 1)
        if call.status == "error":
            u.add(f"{prefix}#errors", 1)
        if call.status == "blocked_by_guardrail":
            u.add(f"{prefix}#blocked", 1)
    return u
