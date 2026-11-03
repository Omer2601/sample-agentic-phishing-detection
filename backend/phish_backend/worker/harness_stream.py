# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Fold the invoke_harness event stream into text, usage and timed tool calls."""

import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime

from phish_backend.common.timeutil import utcnow
from phish_contracts.models import Call, CallKind, Usage, tool_agent

logger = logging.getLogger(__name__)


@dataclass
class CycleTiming:
    """One streamed message, in ms from the start of consume().

    first_output_ms is the first text, reasoning or toolUse block: for an assistant
    message that is the model's time to first token as the worker sees it.
    """

    role: str
    start_ms: int
    first_output_ms: int | None = None
    end_ms: int | None = None
    stop_reason: str | None = None


@dataclass
class HarnessOutcome:
    usage: Usage
    text: str = ""
    cycles: int = 0
    stop_reasons: list[str] = field(default_factory=list)
    tool_calls: list[Call] = field(default_factory=list)
    truncated: bool = False
    # Stream timing: without it a slow scan cannot be split into harness start-up, model
    # time to first token, tool wait and final-answer generation (see timing_summary).
    first_event_ms: int | None = None
    end_ms: int = 0
    cycle_timings: list[CycleTiming] = field(default_factory=list)
    reasoning_chars: int = 0
    model_latency_ms: list[int] = field(default_factory=list)

    def timing_summary(self) -> dict:
        assistant = [c for c in self.cycle_timings if c.role == "assistant"]
        ttft = [c.first_output_ms - c.start_ms for c in assistant if c.first_output_ms is not None]
        final = assistant[-1] if assistant else None
        return {
            "harness_first_event_ms": self.first_event_ms,
            "harness_ttft_ms": ttft,
            "harness_tool_wait_ms": sum(c.duration_ms for c in self.tool_calls),
            "harness_final_answer_ms": (self.end_ms - final.start_ms) if final else None,
            "harness_reasoning_chars": self.reasoning_chars,
            "harness_model_latency_ms": self.model_latency_ms,
            "harness_stop_reasons": self.stop_reasons,
        }


def specialist_name(tool_name: str) -> str:
    # The Gateway prefixes every tool with its hyphenated target name: "url-analyst___analyze".
    return tool_agent(tool_name)


def _as_int(value) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def consume(
    events: Iterable,
    *,
    model_id: str,
    clock: Callable[[], float] = time.monotonic,
    wall: Callable[[], datetime] = utcnow,
    max_chars: int = 200_000,
) -> HarnessOutcome:
    outcome = HarnessOutcome(usage=Usage(model_id=model_id))
    open_calls: list[tuple[str, float, datetime]] = []
    input_tokens = output_tokens = cache_read = cache_write = 0
    origin = clock()

    def elapsed() -> int:
        return int((clock() - origin) * 1000)

    def mark_output() -> None:
        cycle = outcome.cycle_timings[-1] if outcome.cycle_timings else None
        if cycle is not None and cycle.first_output_ms is None:
            cycle.first_output_ms = elapsed()

    def close_open() -> None:
        now = clock()
        for name, started, started_wall in open_calls:
            outcome.tool_calls.append(
                Call(
                    kind=CallKind.SPECIALIST,
                    name=name,
                    started_at=started_wall,
                    duration_ms=int((now - started) * 1000),
                    status="ok",
                )
            )
        open_calls.clear()

    for event in events:
        if not isinstance(event, dict):
            continue
        if outcome.first_event_ms is None:
            outcome.first_event_ms = elapsed()
        message_start = event.get("messageStart")
        if isinstance(message_start, dict):
            close_open()
            outcome.cycles += 1
            role = str(message_start.get("role") or "assistant")[:16]
            outcome.cycle_timings.append(CycleTiming(role=role, start_ms=elapsed()))
        start = (event.get("contentBlockStart") or {}).get("start") or {}
        tool_use = start.get("toolUse") if isinstance(start, dict) else None
        if isinstance(tool_use, dict):
            mark_output()
            name = str(tool_use.get("name") or "unknown")[:128]
            open_calls.append((specialist_name(name), clock(), wall()))
        delta = (event.get("contentBlockDelta") or {}).get("delta") or {}
        reasoning = delta.get("reasoningContent") if isinstance(delta, dict) else None
        if isinstance(reasoning, dict):
            mark_output()
            if isinstance(reasoning.get("text"), str):
                outcome.reasoning_chars += len(reasoning["text"])
        if isinstance(delta, dict) and isinstance(delta.get("text"), str):
            mark_output()
            room = max_chars - len(outcome.text)
            if room > 0:
                outcome.text += delta["text"][:room]
            if len(delta["text"]) > room and not outcome.truncated:
                outcome.truncated = True
                logger.warning(
                    "orchestrator output exceeded %d characters; the rest is discarded", max_chars
                )
        stop = event.get("messageStop") or {}
        if isinstance(stop, dict) and stop.get("stopReason"):
            outcome.stop_reasons.append(str(stop["stopReason"])[:64])
        if isinstance(event.get("messageStop"), dict) and outcome.cycle_timings:
            outcome.cycle_timings[-1].end_ms = elapsed()
            if isinstance(stop, dict) and stop.get("stopReason"):
                outcome.cycle_timings[-1].stop_reason = str(stop["stopReason"])[:64]
        metadata = event.get("metadata") or {}
        usage = metadata.get("usage") if isinstance(metadata, dict) else None
        if isinstance(usage, dict):
            cache_read += _as_int(usage.get("cacheReadInputTokens"))
            cache_write += _as_int(usage.get("cacheWriteInputTokens"))
            input_tokens += _as_int(usage.get("inputTokens"))
            output_tokens += _as_int(usage.get("outputTokens"))
        metrics = metadata.get("metrics") if isinstance(metadata, dict) else None
        if isinstance(metrics, dict) and "latencyMs" in metrics:
            outcome.model_latency_ms.append(_as_int(metrics.get("latencyMs")))
    close_open()
    outcome.end_ms = elapsed()
    outcome.usage = Usage(
        input_tokens=input_tokens + cache_read + cache_write,
        output_tokens=output_tokens,
        model_id=model_id,
        cache_read_tokens=cache_read,
        cache_write_tokens=cache_write,
    )
    return outcome
