# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Run one specialist turn on Bedrock with structured output and a single guardrail retry."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from importlib import resources

from botocore.config import Config
from botocore.exceptions import ClientError
from strands import Agent
from strands.models import BedrockModel
from strands.models.model import CacheConfig

from phish_agents.common.finding import FindingDraft
from phish_agents.common.timing import CallRecorder
from phish_contracts.models import CallKind, Usage

logger = logging.getLogger(__name__)

DEFAULT_MODEL_ID = "global.anthropic.claude-sonnet-5-5"
BLOCK_STOP_REASONS = frozenset({"guardrail_intervened", "content_filtered"})
_CONTENT_FILTER_ERROR_CODE = "validationexception"
_CONTENT_FILTER_MESSAGE = "content filtering policy"

# Adaptive mode adds client-side rate limiting on top of exponential backoff for
# ThrottlingException. Attempts and read timeout stay small because the whole analysis
# has a 30 s deadline (common/server.py); a long retry tail would only hit that wall.
_BOTO_CONFIG = Config(
    retries={"total_max_attempts": 3, "mode": "adaptive"}, connect_timeout=5, read_timeout=30
)


def model_id() -> str:
    return os.environ.get("MODEL_ID", DEFAULT_MODEL_ID)


_CACHE_OFF = frozenset({"0", "false", "off", "no"})


def prompt_cache_enabled() -> bool:
    """PHISH_PROMPT_CACHE, default on. Set to 0/false/off/no to send no cache points."""
    return os.environ.get("PHISH_PROMPT_CACHE", "1").strip().lower() not in _CACHE_OFF


class _PrefixCacheBedrockModel(BedrockModel):
    """Cache points after the tools and the system prompt only, none on the last message.

    For an agent whose last message before its answer is a large tool result (code_analyst:
    about 15k tokens of page code), the message cache point is written at 1.25 times the input
    price and never read: the answer is the last model call. Measured on the sandbox before this
    change: code_analyst wrote 6.75M cache tokens and read 1.66M.
    """

    def _inject_cache_point(self, messages, dynamic_trailing_blocks: int = 0) -> None:
        return None


def bedrock_model(
    model_id_override: str | None = None, cache_messages: bool = True
) -> BedrockModel:
    extra: dict = {}
    if prompt_cache_enabled():
        # Bedrock Converse prompt caching: strategy "auto" resolves to the Anthropic format for
        # Claude model ids and puts one cachePoint after the tool definitions (tools_ttl=True)
        # and one after the system prompt, so the static prefix (tools + prompt) is cached and
        # only the URL turn is new. The default 5 minute TTL fits a scan burst. A prefix below the
        # model's minimum cacheable length (about 1,024 tokens for Claude; check the Bedrock
        # prompt caching page for Sonnet 5.5) is silently not cached, so cache_write stays 0.
        extra["cache_config"] = CacheConfig(strategy="auto", tools_ttl=True)
    cls = BedrockModel if cache_messages else _PrefixCacheBedrockModel
    return cls(
        model_id=model_id_override or model_id(),
        region_name=os.environ["AWS_REGION"],
        max_tokens=1500,
        boto_client_config=_BOTO_CONFIG,
        **extra,
    )


def load_prompt(package: str) -> str:
    return resources.files(package).joinpath("prompt.md").read_text(encoding="utf-8")


@dataclass
class AgentRun:
    draft: FindingDraft | None
    usage: Usage
    blocked: bool


def _usage_from(metrics_usage: dict) -> tuple[int, int]:
    """Prompt tokens including cache reads and writes, and output tokens."""
    cread, cwrite = _cache_from(metrics_usage)
    tin = int(metrics_usage.get("inputTokens", 0)) + cread + cwrite
    return tin, int(metrics_usage.get("outputTokens", 0))


def _cache_from(metrics_usage: dict) -> tuple[int, int]:
    """Cache read and write tokens. Bedrock reports them apart from inputTokens."""
    return (
        int(metrics_usage.get("cacheReadInputTokens", 0)),
        int(metrics_usage.get("cacheWriteInputTokens", 0)),
    )


def _block_stop_reason(exc: BaseException) -> str | None:
    """The guardrail stop reason an exception carries in structured data, else None.

    Checked on the exception and everywhere in its __cause__/__context__ chain (Strands and
    the event loop may wrap the botocore error): a `stop_reason` attribute or a Bedrock-style
    `response` whose `stopReason` is in BLOCK_STOP_REASONS, or a Bedrock content-filter
    refusal, which arrives as a ValidationException error code (`validationException` on a
    ConverseStream event) naming the content filtering policy. Anything else, whatever its
    message says, is not a refusal and is re-raised.
    """
    seen: set[int] = set()
    pending: list[BaseException] = [exc]
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        stop = getattr(current, "stop_reason", None)
        if isinstance(stop, str) and stop in BLOCK_STOP_REASONS:
            return stop
        response = getattr(current, "response", None)
        if isinstance(response, dict):
            stop = response.get("stopReason")
            if isinstance(stop, str) and stop in BLOCK_STOP_REASONS:
                return stop
            if isinstance(current, ClientError) and _is_content_filter_refusal(response):
                return "content_filtered"
        pending.extend(link for link in (current.__cause__, current.__context__) if link)
    return None


def _is_content_filter_refusal(response: dict) -> bool:
    error = response.get("Error")
    if not isinstance(error, dict):
        return False
    code = str(error.get("Code", "")).lower()
    message = str(error.get("Message", "")).lower()
    return code == _CONTENT_FILTER_ERROR_CODE and _CONTENT_FILTER_MESSAGE in message


async def run_specialist(
    *,
    name: str,
    system_prompt: str,
    user_text: str,
    tools: list,
    recorder: CallRecorder,
    on_retry: Callable[[], str],
    agent_factory=Agent,
    cache_messages: bool = True,
) -> AgentRun:
    total_in = total_out = total_cread = total_cwrite = 0
    blocked = False
    mid = model_id()

    def usage(tin: int, tout: int, cread: int, cwrite: int) -> Usage:
        return Usage(
            input_tokens=tin,
            output_tokens=tout,
            model_id=mid,
            cache_read_tokens=cread,
            cache_write_tokens=cwrite,
        )

    for attempt in range(2):
        prompt = user_text if attempt == 0 else on_retry()
        agent = agent_factory(
            model=bedrock_model(cache_messages=cache_messages),
            system_prompt=system_prompt,
            tools=tools,
            name=name,
            callback_handler=None,
        )
        with recorder.record(CallKind.MODEL, name) as handle:
            try:
                result = await agent.invoke_async(prompt, structured_output_model=FindingDraft)
            except Exception as exc:
                block_reason = _block_stop_reason(exc)
                if block_reason is None:
                    raise
                blocked = True
                tin, tout = _usage_from(agent.event_loop_metrics.accumulated_usage)
                cread, cwrite = _cache_from(agent.event_loop_metrics.accumulated_usage)
                total_in, total_out = total_in + tin, total_out + tout
                total_cread, total_cwrite = total_cread + cread, total_cwrite + cwrite
                handle.status = "blocked_by_guardrail"
                handle.usage = usage(tin, tout, cread, cwrite)
                logger.info(
                    "usage agent=%s model=%s in=%d out=%d attempt=%d cache_read=%d cache_write=%d",
                    name,
                    mid,
                    tin,
                    tout,
                    attempt + 1,
                    cread,
                    cwrite,
                )
                logger.warning(
                    "guardrail block agent=%s attempt=%d via exception stop=%s",
                    name,
                    attempt + 1,
                    block_reason,
                )
                continue
            tin, tout = _usage_from(result.metrics.accumulated_usage)
            cread, cwrite = _cache_from(result.metrics.accumulated_usage)
            total_in, total_out = total_in + tin, total_out + tout
            total_cread, total_cwrite = total_cread + cread, total_cwrite + cwrite
            handle.usage = usage(tin, tout, cread, cwrite)
            logger.info(
                "usage agent=%s model=%s in=%d out=%d attempt=%d cache_read=%d cache_write=%d",
                name,
                mid,
                tin,
                tout,
                attempt + 1,
                cread,
                cwrite,
            )
            stop_reason = str(result.stop_reason)
            if stop_reason in BLOCK_STOP_REASONS:
                handle.status = "blocked_by_guardrail"
                blocked = True
                logger.warning(
                    "guardrail block agent=%s attempt=%d stop=%s", name, attempt + 1, stop_reason
                )
                continue
            if result.structured_output is None:
                # Not a refusal: e.g. max_tokens cut the JSON short or the reply was malformed.
                handle.status = "error"
                blocked = False
                logger.warning(
                    "no structured output agent=%s attempt=%d stop=%s",
                    name,
                    attempt + 1,
                    stop_reason,
                )
                continue
            return AgentRun(
                result.structured_output,
                usage(total_in, total_out, total_cread, total_cwrite),
                False,
            )
    # blocked reflects the last attempt: a guardrail refusal, or else no usable answer.
    return AgentRun(None, usage(total_in, total_out, total_cread, total_cwrite), blocked)
