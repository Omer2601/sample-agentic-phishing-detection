# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Throttle-only retry for the non-idempotent harness call, plus session housekeeping.

Only throttling (and a runtime that never became healthy, where nothing ran) is
retried. A read timeout or mid-flight error may already have run the orchestration,
so repeating it could double the cost of a scan.
"""

import hashlib
import logging
import random
import re
import time
from collections.abc import Callable

from botocore.exceptions import BotoCoreError, ClientError

from phish_backend.common.clients import HARNESS_READ_TIMEOUT_SECONDS

logger = logging.getLogger(__name__)

THROTTLE_ERROR_CODES = frozenset(
    {"ThrottlingException", "ThrottledException", "TooManyRequestsException"}
)
_NOT_READY_MARKERS = (
    "health check failed",
    "health check timed out",
    "initialization time exceeded",
)
MAX_ATTEMPTS = 6
_BASE_SECONDS = 1.0
_CAP_SECONDS = 20.0
_SLEEP_BUDGET_SECONDS = 60.0
# A retry after sleeping must still fit a full harness call (read timeout) plus time to
# record the outcome, or the Lambda dies mid-call and the scan waits for the claim lease.
_MARGIN_SECONDS = 15.0
_RESERVE_SECONDS = HARNESS_READ_TIMEOUT_SECONDS + _MARGIN_SECONDS
_SESSION_UNSAFE = re.compile(r"[^A-Za-z0-9-]")

_lambda_context = None


class ThrottleDeferred(Exception):
    """Throttled with no time left for another full call: hand the message back to SQS.

    Nothing ran, so the caller releases the scan without spending one of its attempts.
    """


def set_lambda_context(ctx) -> None:
    global _lambda_context
    _lambda_context = ctx


def remaining_seconds(default: float = 300.0) -> float:
    getter = getattr(_lambda_context, "get_remaining_time_in_millis", None)
    if getter is None:
        return default
    try:
        return max(0.0, float(getter()) / 1000.0)
    except (TypeError, ValueError):
        return default


def _code(exc: BaseException) -> str:
    if isinstance(exc, ClientError):
        return str(exc.response.get("Error", {}).get("Code", ""))
    return ""


def is_runtime_not_ready(exc: BaseException) -> bool:
    return _code(exc) == "RuntimeClientError" and any(
        m in str(exc).lower() for m in _NOT_READY_MARKERS
    )


def _retry_after(exc: BaseException) -> float | None:
    if not isinstance(exc, ClientError):
        return None
    headers = exc.response.get("ResponseMetadata", {}).get("HTTPHeaders", {}) or {}
    raw = headers.get("retry-after") or headers.get("Retry-After")
    try:
        value = float(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None
    return value if value is not None and value >= 0 else None


def invoke_with_throttle_retry[T](
    call: Callable[[], T], *, what: str, sleep: Callable[[float], None] = time.sleep
) -> T:
    budget = _SLEEP_BUDGET_SECONDS
    last: BaseException | None = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            return call()
        except ClientError as exc:
            if _code(exc) not in THROTTLE_ERROR_CODES and not is_runtime_not_ready(exc):
                raise
            last = exc
            if attempt == MAX_ATTEMPTS:
                break
            window = min(_CAP_SECONDS, _BASE_SECONDS * 2 ** (attempt - 1))
            hinted = _retry_after(exc)
            headroom = remaining_seconds() - _RESERVE_SECONDS
            if headroom <= 0:
                logger.warning(
                    "%s throttled on attempt %d with no room for another call; redelivering",
                    what,
                    attempt,
                )
                raise ThrottleDeferred(what) from exc
            if budget <= 0:
                logger.warning("%s throttled on attempt %d; sleep budget spent", what, attempt)
                break
            # Full jitter; jitter needs no cryptographic randomness.
            delay = hinted if hinted is not None else random.uniform(0.0, window)  # noqa: S311
            delay = min(delay, budget, headroom)
            budget -= delay
            logger.warning(
                "%s throttled (%s) on attempt %d of %d; sleeping %.2fs",
                what,
                _code(exc),
                attempt,
                MAX_ATTEMPTS,
                delay,
            )
            sleep(delay)
    if last is None:
        raise RuntimeError(f"{what} did not run")
    raise last


def scan_session_id(scan_id: str, attempt: int) -> str:
    """`{scan_id}-a{attempt}`: a fresh harness session per attempt, so no attempt sees an
    earlier attempt's conversation. AgentCore needs 33 to 256 characters; only
    [A-Za-z0-9-] is used. Short ids are padded with a hash of the id before the suffix.
    """
    suffix = f"-a{attempt}"
    base = _SESSION_UNSAFE.sub("-", (scan_id or "").strip())
    if len(base) + len(suffix) < 33:
        base = f"{base}-{hashlib.sha256(base.encode()).hexdigest()}"
    return base[: 256 - len(suffix)] + suffix


def stop_harness_session(client, session_id: str, harness_arn: str) -> bool:
    """Release the harness session so idle sessions do not hold quota. Never raises."""
    try:
        client.stop_runtime_session(runtimeSessionId=session_id, agentRuntimeArn=harness_arn)
    except ClientError as exc:
        if _code(exc) == "ResourceNotFoundException":
            return True
        logger.warning(
            "StopRuntimeSession failed for %s (%s); the session will idle out",
            session_id,
            _code(exc),
        )
        return False
    except BotoCoreError as exc:
        # Connection and read errors: the session idles out, and the scan result stands.
        logger.warning(
            "StopRuntimeSession failed for %s (%s); the session will idle out",
            session_id,
            type(exc).__name__,
        )
        return False
    return True
