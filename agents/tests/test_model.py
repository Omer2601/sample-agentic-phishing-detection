# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import logging

import pytest
from agent_fakes import FakeAgentFactory, FakeResult
from botocore.exceptions import ClientError, EventStreamError

from phish_agents.common import model
from phish_agents.common.finding import FindingDraft
from phish_agents.common.timing import CallRecorder

DRAFT = FindingDraft(verdict="legitimate", confidence=70, signals=[])


class GuardrailStop(Exception):
    """An error carrying the model's stop reason as a structured field."""

    def __init__(self, stop_reason: str, message: str = "model stopped"):
        super().__init__(message)
        self.stop_reason = stop_reason


def client_error(code: str, message: str, **response) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}, **response}, "Converse")


async def run(factory, on_retry=lambda: "sanitized"):
    rec = CallRecorder()
    result = await model.run_specialist(
        name="url_analyst",
        system_prompt="sys",
        user_text="first",
        tools=[],
        recorder=rec,
        on_retry=on_retry,
        agent_factory=factory,
    )
    return result, rec


async def test_success_first_try():
    factory = FakeAgentFactory([FakeResult(DRAFT)])
    result, rec = await run(factory)
    assert result.draft == DRAFT and not result.blocked
    assert result.usage.input_tokens == 100 and result.usage.model_id == model.DEFAULT_MODEL_ID
    assert [c.status for c in rec.calls] == ["ok"]


async def test_guardrail_stop_reason_then_success_uses_retry_text():
    factory = FakeAgentFactory(
        [FakeResult(None, stop_reason="guardrail_intervened"), FakeResult(DRAFT)]
    )
    result, rec = await run(factory)
    assert factory.prompts == ["first", "sanitized"]
    assert result.draft == DRAFT and result.usage.input_tokens == 200
    assert [c.status for c in rec.calls] == ["blocked_by_guardrail", "ok"]


async def test_blocked_twice_returns_blocked():
    factory = FakeAgentFactory(
        [
            GuardrailStop("content_filtered"),
            FakeResult(None, stop_reason="content_filtered"),
        ]
    )
    result, rec = await run(factory)
    assert result.blocked and result.draft is None
    assert [c.status for c in rec.calls] == ["blocked_by_guardrail", "blocked_by_guardrail"]


async def test_other_errors_propagate():
    factory = FakeAgentFactory([ValueError("bad request")])
    try:
        await run(factory)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_bedrock_model_uses_adaptive_retries():
    m = model.bedrock_model()
    cfg = m.config
    assert cfg["model_id"] == "global.anthropic.claude-sonnet-5-5"


def test_load_prompt_reads_package_file():
    assert "url" in model.load_prompt("phish_agents.url_analyst").lower()


def test_bedrock_client_retries_briefly_with_short_read_timeout():
    cfg = model._BOTO_CONFIG
    assert cfg.retries["total_max_attempts"] == 3
    assert cfg.read_timeout == 30


async def test_guardrail_exception_path_logs_token_usage(caplog):
    factory = FakeAgentFactory([GuardrailStop("guardrail_intervened"), FakeResult(DRAFT)])
    with caplog.at_level(logging.INFO, logger="phish_agents.common.model"):
        await run(factory)
    usage_lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("usage ")]
    assert any("in=50 out=0 attempt=1" in line for line in usage_lines), usage_lines


def test_bedrock_model_sends_no_temperature(monkeypatch):
    # Sonnet 5.5 rejects the parameter ("`temperature` is deprecated for this model"); every
    # specialist call failed in the first API e2e (2026-09-29).
    from phish_agents.common import model as model_module

    monkeypatch.setenv("AWS_REGION", "us-west-2")
    config = model_module.bedrock_model().get_config()
    assert "temperature" not in config or config["temperature"] is None
    assert "top_p" not in config or config["top_p"] is None


def _request(m, tools=True):
    spec = {"name": "t", "description": "d", "inputSchema": {"json": {"type": "object"}}}
    return m.format_request(
        [{"role": "user", "content": [{"text": "hi"}]}],
        [spec] if tools else None,
        system_prompt_content=[{"text": "SYSTEM"}],
    )


def _cache_points(m, tools=True):
    request = _request(m, tools)
    return request["system"], request.get("toolConfig", {}).get("tools", [])


def _message_cache_points(m):
    return [b for msg in _request(m)["messages"] for b in msg["content"] if "cachePoint" in b]


def test_message_cache_point_by_default(monkeypatch):
    monkeypatch.delenv("PHISH_PROMPT_CACHE", raising=False)
    assert len(_message_cache_points(model.bedrock_model())) == 1


def test_prefix_only_cache_keeps_system_and_tools_but_not_the_message(monkeypatch):
    monkeypatch.delenv("PHISH_PROMPT_CACHE", raising=False)
    m = model.bedrock_model(cache_messages=False)
    system, tools = _cache_points(m)
    assert system[-1] == {"cachePoint": {"type": "default"}}
    assert tools[-1] == {"cachePoint": {"type": "default"}}
    assert _message_cache_points(m) == []


def test_prompt_cache_is_on_by_default_after_system_and_tools(monkeypatch):
    monkeypatch.delenv("PHISH_PROMPT_CACHE", raising=False)
    system, tools = _cache_points(model.bedrock_model())
    assert system[-1] == {"cachePoint": {"type": "default"}} and system[0] == {"text": "SYSTEM"}
    assert tools[-1] == {"cachePoint": {"type": "default"}}


@pytest.mark.parametrize("value", ["0", "false", "OFF", "no"])
def test_prompt_cache_can_be_switched_off(monkeypatch, value):
    monkeypatch.setenv("PHISH_PROMPT_CACHE", value)
    assert not model.prompt_cache_enabled()
    system, tools = _cache_points(model.bedrock_model())
    assert system == [{"text": "SYSTEM"}]
    assert all("cachePoint" not in block for block in tools)


async def test_usage_log_line_carries_cache_read_and_write_tokens(caplog):
    import logging

    result = FakeResult(DRAFT)
    result.metrics.accumulated_usage.update(cacheReadInputTokens=900, cacheWriteInputTokens=40)
    with caplog.at_level(logging.INFO, logger="phish_agents.common.model"):
        await run(FakeAgentFactory([result]))
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("usage ")]
    assert any("cache_read=900 cache_write=40" in line for line in lines), lines


async def test_usage_log_line_has_zero_cache_counts_when_absent(caplog):
    import logging

    with caplog.at_level(logging.INFO, logger="phish_agents.common.model"):
        await run(FakeAgentFactory([FakeResult(DRAFT)]))
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("usage ")]
    assert any("cache_read=0 cache_write=0" in line for line in lines), lines


async def test_finding_usage_counts_cached_prompt_tokens():
    # Bedrock reports cache reads and writes apart from inputTokens; with caching on, the
    # uncached remainder was about 6 tokens per call and the Finding's cost left out the rest.
    result = FakeResult(DRAFT)
    result.metrics.accumulated_usage.update(cacheReadInputTokens=900, cacheWriteInputTokens=40)
    out, _ = await run(FakeAgentFactory([result]))
    assert out.usage.input_tokens == 100 + 900 + 40
    assert (out.usage.cache_read_tokens, out.usage.cache_write_tokens) == (900, 40)


@pytest.mark.parametrize(
    "exc",
    [
        RuntimeError("Input blocked by content filtering policy"),
        RuntimeError("blocked by guardrail"),
        ValueError("guardrail configuration missing"),
        client_error("ThrottlingException", "Request blocked by rate limiter"),
        client_error("ValidationException", "content filter: unsupported parameter"),
        client_error("AccessDeniedException", "blocked by an explicit deny in a guardrail policy"),
        GuardrailStop("end_turn", "blocked by something unrelated"),
    ],
    ids=[
        "runtime-filter-text",
        "runtime-guardrail-text",
        "value-guardrail-text",
        "throttling",
        "validation",
        "access-denied",
        "non-block-stop-reason",
    ],
)
async def test_errors_that_only_mention_a_block_propagate(exc):
    factory = FakeAgentFactory([exc, FakeResult(DRAFT)])
    with pytest.raises(type(exc)) as raised:
        await run(factory)
    assert raised.value is exc
    assert factory.prompts == ["first"]


@pytest.mark.parametrize(
    "exc",
    [
        GuardrailStop("guardrail_intervened"),
        GuardrailStop("content_filtered"),
        client_error(
            "ModelStreamErrorException", "stream ended", stopReason="guardrail_intervened"
        ),
    ],
    ids=["stop-reason-attr", "content-filtered-attr", "response-stop-reason"],
)
async def test_structured_block_errors_are_treated_as_refusals(exc):
    factory = FakeAgentFactory([exc, FakeResult(DRAFT)])
    result, rec = await run(factory)
    assert result.draft == DRAFT
    assert factory.prompts == ["first", "sanitized"]
    assert [c.status for c in rec.calls] == ["blocked_by_guardrail", "ok"]


async def test_a_block_wrapped_by_another_error_is_found_through_the_cause_chain():
    try:
        try:
            raise GuardrailStop("guardrail_intervened")
        except GuardrailStop as inner:
            raise RuntimeError("agent loop failed") from inner
    except RuntimeError as wrapped:
        exc = wrapped
    factory = FakeAgentFactory([exc, FakeResult(DRAFT)])
    result, rec = await run(factory)
    assert result.draft == DRAFT
    assert [c.status for c in rec.calls] == ["blocked_by_guardrail", "ok"]


def test_block_detection_ignores_message_text_and_survives_cycles():
    a = RuntimeError("guardrail blocked by content filter")
    b = RuntimeError("other")
    a.__cause__, b.__cause__ = b, a
    assert model._block_stop_reason(a) is None
    assert model._block_stop_reason(GuardrailStop("guardrail_intervened")) == "guardrail_intervened"


async def test_no_structured_output_is_not_reported_as_a_guardrail_block(caplog):
    factory = FakeAgentFactory(
        [FakeResult(None, stop_reason="max_tokens"), FakeResult(None, stop_reason="end_turn")]
    )
    with caplog.at_level(logging.WARNING, logger="phish_agents.common.model"):
        result, rec = await run(factory)
    assert result.draft is None and result.blocked is False
    assert factory.prompts == ["first", "sanitized"]
    assert [c.status for c in rec.calls] == ["error", "error"]
    messages = [r.getMessage() for r in caplog.records]
    assert any(m.startswith("no structured output") and "stop=max_tokens" in m for m in messages)
    assert not any(m.startswith("guardrail block") for m in messages)


async def test_truncated_reply_then_success_returns_the_draft():
    factory = FakeAgentFactory([FakeResult(None, stop_reason="max_tokens"), FakeResult(DRAFT)])
    result, rec = await run(factory)
    assert result.draft == DRAFT and not result.blocked
    assert [c.status for c in rec.calls] == ["error", "ok"]


async def test_last_attempt_decides_between_block_and_unusable_output():
    factory = FakeAgentFactory(
        [
            FakeResult(None, stop_reason="max_tokens"),
            FakeResult(None, stop_reason="guardrail_intervened"),
        ]
    )
    result, rec = await run(factory)
    assert result.blocked is True
    assert [c.status for c in rec.calls] == ["error", "blocked_by_guardrail"]


def bedrock_error(code, message, cls=ClientError):
    return cls({"Error": {"Code": code, "Message": message}}, "ConverseStream")


def content_filter_refusal():
    return bedrock_error("ValidationException", "Output blocked by content filtering policy")


@pytest.mark.parametrize(
    "exc",
    [
        content_filter_refusal(),
        bedrock_error(
            "validationException",
            "Output blocked by content filtering policy",
            cls=EventStreamError,
        ),
    ],
    ids=["client-error", "event-stream-error"],
)
def test_bedrock_content_filter_refusal_is_a_block(exc):
    assert model._block_stop_reason(exc) == "content_filtered"


def test_a_refusal_reached_only_through_the_context_is_a_block():
    outer = RuntimeError("event loop failed")
    outer.__cause__ = ValueError("unrelated cause")
    outer.__context__ = content_filter_refusal()
    assert model._block_stop_reason(outer) == "content_filtered"


@pytest.mark.parametrize(
    "exc",
    [
        bedrock_error("ValidationException", "guardrailIdentifier is invalid"),
        bedrock_error("ThrottlingException", "content filtering policy throttled"),
        bedrock_error("AccessDeniedException", "Request blocked by an explicit deny"),
        RuntimeError("Input blocked by content filtering policy"),
    ],
    ids=["validation-not-filter", "throttling-mentions-filter", "access-denied", "plain-text"],
)
def test_bedrock_errors_that_are_not_refusals_are_not_blocks(exc):
    assert model._block_stop_reason(exc) is None


async def test_a_wrapped_content_filter_refusal_is_retried_then_succeeds():
    try:
        try:
            raise content_filter_refusal()
        except ClientError as inner:
            raise RuntimeError("event loop failed") from inner
    except RuntimeError as outer:
        wrapped = outer
    factory = FakeAgentFactory([wrapped, FakeResult(DRAFT)])
    result, _ = await run(factory)
    assert result.draft == DRAFT and not result.blocked
    assert factory.prompts == ["first", "sanitized"]
