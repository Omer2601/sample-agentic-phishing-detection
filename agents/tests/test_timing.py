# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import pytest

from phish_agents.common.timing import CallRecorder
from phish_contracts.models import CallKind, Usage


def test_records_ok_call_with_duration():
    rec = CallRecorder()
    with rec.record(CallKind.WHOIS, "whois_lookup") as handle:
        handle.usage = Usage(input_tokens=1, output_tokens=2, model_id="m")
    (call,) = rec.calls
    assert call.kind == "whois" and call.status == "ok" and call.duration_ms >= 0
    assert call.usage.output_tokens == 2


def test_records_error_and_reraises():
    rec = CallRecorder()
    with pytest.raises(RuntimeError), rec.record(CallKind.BROWSER, "brand_visual"):
        raise RuntimeError("boom")
    assert rec.calls[0].status == "error"


def test_explicit_blocked_status_kept():
    rec = CallRecorder()
    with rec.record(CallKind.MODEL, "code_analyst") as handle:
        handle.status = "blocked_by_guardrail"
    assert rec.calls[0].status == "blocked_by_guardrail"


async def _cancelled_call(rec: CallRecorder, keep_cancelled: bool) -> None:
    import asyncio

    async def work():
        with rec.record(CallKind.WHOIS, "whois_lookup", keep_cancelled=keep_cancelled):
            await asyncio.Event().wait()

    task = asyncio.ensure_future(work())
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_cancelled_call_is_an_error_row_by_default():
    rec = CallRecorder()
    await _cancelled_call(rec, keep_cancelled=True)
    assert [c.status for c in rec.calls] == ["error"]


async def test_cancelled_speculative_call_leaves_no_row_and_still_propagates():
    rec = CallRecorder()
    await _cancelled_call(rec, keep_cancelled=False)
    assert rec.calls == []


def test_speculative_call_that_fails_is_still_an_error_row():
    rec = CallRecorder()
    with (
        pytest.raises(RuntimeError),
        rec.record(CallKind.WHOIS, "whois_lookup", keep_cancelled=False),
    ):
        raise RuntimeError("rdap down")
    assert [c.status for c in rec.calls] == ["error"]
