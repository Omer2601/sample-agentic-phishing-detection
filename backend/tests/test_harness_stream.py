# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
from datetime import UTC, datetime

from phish_backend.worker.harness_stream import consume, specialist_name


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def tool(name):
    return {"contentBlockStart": {"start": {"toolUse": {"name": name, "toolUseId": "t"}}}}


def text(s):
    return {"contentBlockDelta": {"delta": {"text": s}}}


def usage(i, o):
    return {"metadata": {"usage": {"inputTokens": i, "outputTokens": o}}}


def run(events, clock):
    def gen():
        for step in events:
            if isinstance(step, float):
                clock.t = step
                continue
            yield step

    return consume(
        gen(),
        model_id="us.anthropic.claude-opus-5-5",
        clock=clock,
        wall=lambda: datetime(2026, 9, 29, tzinfo=UTC),
    )


def test_specialist_name():
    assert specialist_name("url-analyst___analyze") == "url_analyst"
    assert specialist_name("plain") == "plain"


def test_parallel_tools_in_one_turn_are_one_cycle_and_timed():
    clock = Clock()
    outcome = run(
        [
            {"messageStart": {"role": "assistant"}},
            1.0,
            tool("url-analyst___analyze"),
            tool("brand-visual___analyze"),
            tool("code-analyst___analyze"),
            {"messageStop": {"stopReason": "tool_use"}},
            usage(1000, 50),
            21.0,
            {"messageStart": {"role": "assistant"}},
            text("<verdict>{}</verdict>"),
            {"messageStop": {"stopReason": "end_turn"}},
            usage(4000, 800),
        ],
        clock,
    )
    assert outcome.cycles == 2
    assert [c.name for c in outcome.tool_calls] == ["url_analyst", "brand_visual", "code_analyst"]
    assert all(c.duration_ms == 20000 for c in outcome.tool_calls)
    assert outcome.usage.input_tokens == 5000
    assert outcome.usage.output_tokens == 850
    assert outcome.stop_reasons == ["tool_use", "end_turn"]
    assert outcome.text == "<verdict>{}</verdict>"


def test_open_tool_call_closed_at_stream_end():
    clock = Clock()
    outcome = run([{"messageStart": {}}, 0.5, tool("x___y"), 3.5], clock)
    assert outcome.tool_calls[0].duration_ms == 3000


def test_text_is_capped():
    clock = Clock()
    outcome = consume(
        iter([text("a" * 10), text("b" * 10)]), model_id="m", clock=clock, max_chars=12
    )
    assert outcome.text == "a" * 10 + "bb"
    assert outcome.truncated


def test_non_dict_events_and_empty_stream():
    outcome = consume(iter(["junk", None]), model_id="m")
    assert outcome.text == "" and outcome.cycles == 0 and outcome.usage.input_tokens == 0


def test_cycle_timing_splits_ttft_tool_wait_and_final_answer():
    clock = Clock()
    outcome = run(
        [
            2.0,
            {"messageStart": {"role": "assistant"}},
            5.0,
            {"contentBlockDelta": {"delta": {"reasoningContent": {"text": "think"}}}},
            tool("registry___search_discoverable_registry_records"),
            6.0,
            {"messageStop": {"stopReason": "tool_use"}},
            {
                "metadata": {
                    "usage": {"inputTokens": 1, "outputTokens": 1},
                    "metrics": {"latencyMs": 4000},
                }
            },
            26.0,
            {"messageStart": {"role": "user"}},
            {"messageStop": {"stopReason": "end_turn"}},
            {"messageStart": {"role": "assistant"}},
            29.0,
            text("<verdict>{}</verdict>"),
            40.0,
            {"messageStop": {"stopReason": "end_turn"}},
            {"metadata": {"metrics": {"latencyMs": 14000}}},
        ],
        clock,
    )
    summary = outcome.timing_summary()
    assert summary["harness_first_event_ms"] == 2000
    # Time to first token per assistant turn: reasoning counts as output.
    assert summary["harness_ttft_ms"] == [3000, 3000]
    assert summary["harness_tool_wait_ms"] == 21000
    assert summary["harness_final_answer_ms"] == 14000
    assert summary["harness_reasoning_chars"] == 5
    assert summary["harness_model_latency_ms"] == [4000, 14000]
    assert [c.role for c in outcome.cycle_timings] == ["assistant", "user", "assistant"]


def test_timing_summary_of_an_empty_stream():
    summary = consume(iter([]), model_id="m").timing_summary()
    assert summary["harness_first_event_ms"] is None
    assert summary["harness_ttft_ms"] == [] and summary["harness_final_answer_ms"] is None


def test_usage_includes_cache_reads_and_writes():
    usage_event = {
        "inputTokens": 5,
        "outputTokens": 7,
        "cacheReadInputTokens": 100,
        "cacheWriteInputTokens": 20,
    }
    usage = consume(iter([{"metadata": {"usage": usage_event}}]), model_id="m").usage
    assert (usage.input_tokens, usage.output_tokens) == (125, 7)
    assert (usage.cache_read_tokens, usage.cache_write_tokens) == (100, 20)
