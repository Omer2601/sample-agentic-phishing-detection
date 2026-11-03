# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""SQS worker: verdict first, report second.

Per URL: an optional precheck (an HTTP 404 or a site that is down answers immediately, no
model), otherwise harness
turn 1 returns the compact verdict, which is stored (status COMPLETE, report_status
PENDING); turn 2 on the same session then writes the full report. Turn 2 can fail without
affecting the verdict.
"""

import json
import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from decimal import Decimal

from botocore.exceptions import BotoCoreError, ClientError

from phish_backend.common import aws_retry, clients, cost, guardrails, log, precheck, store
from phish_backend.common.config import settings
from phish_backend.common.timeutil import ms_between, utcnow
from phish_backend.worker import direct, scan_memory
from phish_backend.worker.findings import clear_findings, load_findings
from phish_backend.worker.harness_stream import HarnessOutcome, consume
from phish_backend.worker.verdict import (
    ReportMissing,
    VerdictMissing,
    judge,
    no_verdict_shape,
    parse_report,
    parse_verdict,
    report_with_note,
)
from phish_contracts.disclaimer import with_disclaimer_markdown
from phish_contracts.models import (
    REPORT_FOLLOWUP_MESSAGE,
    Call,
    CallKind,
    Finding,
    FindingStatus,
    ReportStatus,
    ScanRecord,
    Usage,
    Verdict,
    build_orchestrator_message,
    build_report_recovery_message,
    error_404_report_markdown,
    error_404_verdict,
    site_down_report_markdown,
    site_down_verdict,
    tools_session_id,
)

logger = logging.getLogger(__name__)
# No scan is dropped: transient failures are retried this many times in total, then FAILED.
MAX_SCAN_ATTEMPTS = 3
BACKOFF_SECONDS = 30
# Turn 2 needs this much time left (minus RESERVE for the write) or the report is FAILED
# with "not enough time" instead of overrunning the Lambda timeout.
REPORT_MIN_SECONDS = 20
REPORT_RESERVE_SECONDS = 15
# tool_agent() of the Gateway `registry` target's tools (registry___search_discoverable_...).
REGISTRY_TOOL_AGENT = "registry"


class RetryableScanError(Exception):
    """The message must go back to SQS; delay_seconds becomes its visibility timeout."""

    def __init__(self, message: str, delay_seconds: int = 0) -> None:
        super().__init__(message)
        self.delay_seconds = delay_seconds


def render_request(url: str, scan_id: str, past_scans: list[str] | None = None) -> str:
    # One definition shared with eval/evaluate_agents.py (concatenation: URLs may contain braces).
    return build_orchestrator_message(url, scan_id, past_scans or [])


def harness_model_override(cfg) -> dict:
    """Per-invocation model config: orchestrator effort and prompt caching, when configured.

    Opus 5.5 cannot turn thinking off; output_config.effort is its only depth control
    (default medium).

    The harness merges additionalParams into the top level of a Bedrock Converse request,
    where a top-level `output_config` is rejected ("Unknown parameter in input"). The model's
    own fields belong in `additionalModelRequestFields`, which Opus 5.5 accepts (verified on a
    live Converse call: effort low produced a shorter answer than medium).

    The Harness has no cache point setting and its system prompt blocks take text only, so
    caching uses Anthropic's top-level `cache_control`, which caches the whole prompt up to the
    last block. Each model call in the tool loop, and the report turn after it, then reads the
    earlier prefix back (verified on Converse with Opus 5.5: turn 2 read the 4,891 tokens turn 1
    wrote). A one-shot call would only pay the write premium, but every scan makes at least two.
    """
    fields: dict = {}
    if cfg.orchestrator_effort:
        fields["output_config"] = {"effort": cfg.orchestrator_effort}
    if cfg.orchestrator_prompt_cache:
        fields["cache_control"] = {"type": "ephemeral"}
    if not fields:
        return {}
    return {
        "model": {
            "bedrockModelConfig": {
                "modelId": cfg.orchestrator_model_id,
                "maxTokens": cfg.harness_max_tokens,
                "additionalParams": {"additionalModelRequestFields": fields},
            }
        }
    }


def handler(event, context):
    log.configure()
    aws_retry.set_lambda_context(context)
    failures = []
    for record in event.get("Records", []):
        try:
            process_message(json.loads(record["body"]))
        except RetryableScanError as exc:
            failures.append({"itemIdentifier": record["messageId"]})
            if exc.delay_seconds and record.get("receiptHandle"):
                _delay_redelivery(record, exc.delay_seconds)
    return {"batchItemFailures": failures}


def _delay_redelivery(record: dict, delay_seconds: int) -> None:
    try:
        clients.sqs().change_message_visibility(
            QueueUrl=settings().scan_queue_url,
            ReceiptHandle=record["receiptHandle"],
            VisibilityTimeout=delay_seconds,
        )
    except (ClientError, BotoCoreError) as exc:
        # The queue's default visibility timeout still redelivers the message, only later.
        logger.warning(
            "could not shorten visibility for %s (%s)", record["messageId"], type(exc).__name__
        )


def _retry_or_fail(record: ScanRecord, token: str, reason: str, **fail_kwargs) -> None:
    """Release the claim for another attempt, or record FAILED after the last one."""
    attempt = record.attempts
    if attempt < MAX_SCAN_ATTEMPTS:
        store.release_scan(record.scan_id, token, error=reason)
        raise RetryableScanError(reason, delay_seconds=BACKOFF_SECONDS * attempt)
    store.fail_scan(
        record.scan_id,
        token,
        error=f"{reason} (failed after {attempt} attempts)",
        completed_at=utcnow(),
        **fail_kwargs,
    )


def _collect_calls(
    harness_call: Call, outcome: HarnessOutcome, findings: list[Finding]
) -> list[Call]:
    """One harness call, any registry lookups, then one specialist call per persisted Finding.

    Specialist timing comes from each Finding's latency_ms, never from the stream: round one
    is one dispatcher___analyze_all call that runs the three specialists concurrently, so the
    stream has one tool call for all three and its timing is not per specialist. The three
    start at the first tool call that is not a lookup (the dispatcher call).

    A registry lookup (a registry___* tool, step 0 with -c agentRegistry=true) writes no
    Finding, so it is the one Gateway call timed from the stream. It is not a specialist: it
    gets its own kind.
    """
    lookups = [c for c in outcome.tool_calls if c.name == REGISTRY_TOOL_AGENT]
    specialist_calls = [c for c in outcome.tool_calls if c.name != REGISTRY_TOOL_AGENT]
    started = specialist_calls[0].started_at if specialist_calls else harness_call.started_at
    calls = [harness_call]
    calls += [c.model_copy(update={"kind": CallKind.REGISTRY}) for c in lookups]
    calls += [
        Call(
            kind=CallKind.SPECIALIST,
            name=f.agent,
            started_at=started,
            duration_ms=f.latency_ms,
            status="ok" if f.status == FindingStatus.OK else f.status.value,
            usage=f.usage,
        )
        for f in findings
    ]
    for finding in findings:
        calls += finding.calls
    return calls


def harness_breakdown(harness_ms: int, invoke_ms: int, outcome: HarnessOutcome) -> dict:
    """Split the orchestrator's wall time so the p95 tail can be attributed.

    model_ms is everything that is not the specialists' tool wait: harness start-up,
    every Opus turn (time to first token plus generation) and the harness's own
    bookkeeping. first_event_ms (from invoke) is session start-up plus the first
    model turn's time to first token.
    """
    summary = outcome.timing_summary()
    first = summary["harness_first_event_ms"]
    summary["harness_invoke_ms"] = invoke_ms
    summary["harness_first_event_ms"] = None if first is None else invoke_ms + first
    summary["harness_model_ms"] = max(0, harness_ms - summary["harness_tool_wait_ms"])
    return summary


def _emit(total_ms: int, harness_ms: int, calls: list[Call], breakdown: dict | None = None) -> None:
    metrics = {"ScanDurationMs": total_ms, "HarnessDurationMs": harness_ms}
    if breakdown:
        for key, name in (
            ("harness_model_ms", "HarnessModelMs"),
            ("harness_tool_wait_ms", "HarnessToolWaitMs"),
            ("harness_first_event_ms", "HarnessFirstEventMs"),
            ("harness_final_answer_ms", "HarnessFinalAnswerMs"),
        ):
            if breakdown.get(key) is not None:
                metrics[name] = breakdown[key]
    log.emit_metrics({"Service": "worker"}, metrics)
    for call in calls:
        log.emit_metrics(
            {"CallKind": call.kind.value, "CallName": call.name},
            {"CallDurationMs": call.duration_ms},
        )


def _precheck(cfg, url: str, scan_id: str, tools_client) -> precheck.PrecheckResult | None:
    """The precheck, or None for "run the normal scan". Never raises."""
    if not cfg.tools_runtime_arn:
        return None
    try:
        client = tools_client or clients.tools_runtime()
        session = tools_session_id(scan_id) if cfg.tools_session_per_scan else None
        result = precheck.precheck_url(
            client, cfg.tools_runtime_arn, url, scan_id, session_id=session
        )
    except Exception as exc:  # noqa: BLE001 - a precheck problem must never fail the scan
        logger.warning("scan %s: precheck skipped (%s)", scan_id, str(exc)[:120])
        return None
    logger.info(
        "scan %s: precheck %s status=%s in %d ms",
        scan_id,
        result.outcome,
        result.final_status,
        result.duration_ms,
    )
    return result


def _fast_path_verdict(url: str, result: precheck.PrecheckResult) -> Verdict:
    if result.is_site_down:
        hops = list(result.hops) or [h for h in (url, result.final_url) if h]
        verdict, report = site_down_verdict(), site_down_report_markdown(url, hops, result.reason)
    else:
        verdict, report = error_404_verdict(), error_404_report_markdown(url, result.final_url)
    return verdict.model_copy(update={"report_markdown": with_disclaimer_markdown(report)})


def _complete_fast_path(record, token, result, started, precheck_started, memory_matches) -> None:
    """error_404 or site_down: a deterministic verdict and report, no model call, READY at once."""
    completed = utcnow()
    total_ms = ms_between(started, completed)
    verdict = _fast_path_verdict(record.url, result)
    calls = [
        Call(
            kind=CallKind.BROWSER,
            name="precheck",
            started_at=precheck_started,
            duration_ms=result.duration_ms,
            status="ok",
        )
    ]
    stored = store.complete_scan(
        record.scan_id,
        token,
        verdict=verdict,
        findings=[],
        calls=calls,
        cost=Decimal("0"),
        completed_at=completed,
        total_ms=total_ms,
        memory_matches=memory_matches,
        report_status=ReportStatus.READY,
    )
    if stored:
        _emit(total_ms, 0, calls)
        label = verdict.verdict.value
        logger.info(
            "scan complete (%s fast path)",
            label,
            extra={"scan_id": record.scan_id, "verdict": label, "total_ms": total_ms},
        )


def _turn(client, cfg, session_id: str, text: str, scan_id: str) -> tuple[HarnessOutcome, int, int]:
    """One InvokeHarness turn on a session: (outcome, invoke_ms, total_ms).

    actorId is the scan id on every turn of a scan. The Harness runs with memory disabled;
    if memory is ever turned on again, a per-scan actor still keeps one scan's events and
    long-term records out of every other scan, and so out of every other user's.
    """
    t0 = time.monotonic()
    response = aws_retry.invoke_with_throttle_retry(
        lambda: client.invoke_harness(
            harnessArn=cfg.harness_arn,
            runtimeSessionId=session_id,
            actorId=scan_id,
            messages=[{"role": "user", "content": [{"text": text}]}],
            **harness_model_override(cfg),
        ),
        what="invoke_harness",
    )
    invoke_ms = int((time.monotonic() - t0) * 1000)
    outcome = consume(response.get("stream", []), model_id=cfg.orchestrator_model_id)
    return outcome, invoke_ms, int((time.monotonic() - t0) * 1000)


def _write_report(
    *,
    client,
    cfg,
    record: ScanRecord,
    token: str,
    verdict: Verdict,
    findings: list[Finding],
    calls: list[Call],
    base_cost: Decimal,
    session_id: str = "",
    message: str = "",
    run_turn=None,
    stop=None,
) -> None:
    """Turn 2: write the report and store it, or mark the report FAILED. Never raises.

    The scan stays COMPLETE either way. The session is stopped at the end, not before.
    run_turn () -> (outcome, invoke_ms, total_ms) replaces the harness turn (direct
    orchestration passes a Converse turn); stop replaces the harness session stop.
    """
    scan_id = record.scan_id
    if run_turn is None:

        def run_turn():
            return _turn(client, cfg, session_id, message, scan_id)

    if stop is None:

        def stop():
            aws_retry.stop_harness_session(client, session_id, cfg.harness_arn)

    started = utcnow()

    def fail(reason: str, outcome: HarnessOutcome | None = None, ms: int = 0) -> None:
        new_calls, new_price = calls, None
        if outcome is not None:
            report_call = Call(
                kind=CallKind.HARNESS,
                name="report",
                started_at=started,
                duration_ms=ms,
                status="error",
                usage=outcome.usage,
            )
            new_calls = [*calls, report_call]
            new_price = cost.price_scan([*_usages(calls, findings), outcome.usage])
        logger.warning("scan %s: report FAILED (%s)", scan_id, reason)
        store.finish_report(
            scan_id,
            token,
            report_status=ReportStatus.FAILED,
            ready_at=utcnow(),
            error=reason,
            calls=new_calls if outcome is not None else None,
            cost=new_price.cost if new_price else None,
            unpriced_models=new_price.unpriced_models if new_price else None,
        )

    try:
        budget = min(
            aws_retry.remaining_seconds() - REPORT_RESERVE_SECONDS,
            float(clients.HARNESS_READ_TIMEOUT_SECONDS),
        )
        if budget < REPORT_MIN_SECONDS:
            fail("not enough time")
            return
        # The boto3 read timeout is per socket read; this bounds the whole turn so the Lambda
        # always has time left to record the outcome.
        pool = ThreadPoolExecutor(max_workers=1)
        try:
            outcome, _, ms = pool.submit(run_turn).result(timeout=budget)
        except FutureTimeout:
            fail("not enough time")
            return
        except aws_retry.ThrottleDeferred:
            fail("the model was throttled")
            return
        except Exception as exc:  # noqa: BLE001 - the verdict stands; only the report is lost
            ref = log.correlation_ref("report_turn", exc)
            fail(f"The report could not be written. Correlation ID: {ref}")
            return
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        try:
            report = report_with_note(parse_report(outcome.text), verdict, findings)
        except ReportMissing as exc:
            ref = log.correlation_ref("parse_report", exc)
            fail(f"The report was not in the expected format. Correlation ID: {ref}", outcome, ms)
            return
        screened, events = guardrails.screen_report(
            verdict.model_copy(update={"report_markdown": report})
        )
        if events:
            store.add_guardrail_events(scan_id, events)
        final = with_disclaimer_markdown(screened.report_markdown)
        report_call = Call(
            kind=CallKind.HARNESS,
            name="report",
            started_at=started,
            duration_ms=ms,
            status="ok",
            usage=outcome.usage,
        )
        price = cost.price_scan([*_usages(calls, findings), outcome.usage])
        total = price.cost
        stored = store.finish_report(
            scan_id,
            token,
            report_status=ReportStatus.READY,
            ready_at=utcnow(),
            report_markdown=final,
            calls=[*calls, report_call],
            cost=total,
            unpriced_models=price.unpriced_models,
        )
        logger.info(
            "report ready",
            extra={
                "scan_id": scan_id,
                "stored": stored,
                "report_ms": ms,
                "cost_usd": str(total),
                "extra_cost_usd": str(total - base_cost),
                "input_tokens": outcome.usage.input_tokens,
                "output_tokens": outcome.usage.output_tokens,
            },
        )
        log.emit_metrics({"Service": "worker"}, {"ReportDurationMs": ms})
    except Exception:  # noqa: BLE001 - last resort: leave the lease to expire, redelivery resumes
        logger.exception("scan %s: report could not be recorded", scan_id)
    finally:
        stop()


def _usages(calls: list[Call], findings: list[Finding]) -> list[Usage]:
    """The usages that are priced: harness calls (orchestrator and report) plus findings."""
    usages = [c.usage for c in calls if c.kind == CallKind.HARNESS and c.usage]
    return [*usages, *(f.usage for f in findings)]


def _resume_report(scan_id: str, agentcore, bedrock=None) -> None:
    """A redelivered message for a scan that already has its verdict.

    The analysis is never re-run. If the report is still PENDING and its lease is free
    (the first worker died), take the lease and write only the report. The first
    conversation is gone with its worker, so this uses a FRESH harness session and a
    message that restates the stored verdict and findings before the follow-up text.
    """
    cfg = settings()
    token = uuid.uuid4().hex
    record = store.claim_report(scan_id, token, utcnow())
    if record is None or record.verdict is None:
        return
    logger.info("scan %s: resuming a PENDING report after redelivery", scan_id)
    recovery = build_report_recovery_message(record.url, scan_id, record.verdict, record.findings)
    if cfg.direct_orchestration:
        _write_report(
            client=None,
            cfg=cfg,
            record=record,
            token=token,
            verdict=record.verdict,
            findings=record.findings,
            calls=record.calls,
            base_cost=record.cost_usd,
            run_turn=_converse_turn(bedrock, cfg, [direct.user(recovery)]),
            stop=lambda: None,
        )
        return
    client = agentcore or clients.agentcore()
    session_id = aws_retry.scan_session_id(scan_id, int(time.time()))
    _write_report(
        client=client,
        cfg=cfg,
        record=record,
        token=token,
        verdict=record.verdict,
        findings=record.findings,
        calls=record.calls,
        base_cost=record.cost_usd,
        session_id=session_id,
        message=recovery,
    )


def _converse_turn(bedrock, cfg, messages: list[dict]):
    """A run_turn for _write_report: one Converse turn, shaped like a harness turn."""

    def run():
        client = bedrock or clients.bedrock_runtime()
        turn, ms = direct.timed(
            lambda: aws_retry.invoke_with_throttle_retry(
                lambda: direct.converse(client, cfg, messages), what="converse"
            )
        )
        return turn, ms, ms

    return run


def _dispatch_safely(client, cfg, url: str, scan_id: str) -> int:
    """Run the three specialists through the dispatcher. Never raises: a failed dispatch leaves
    findings missing in S3, and those become error findings as on the harness path."""
    try:
        if cfg.direct_specialists:
            arns = dict(cfg.specialist_runtime_arns)
            return direct.dispatch_specialists(client, arns, url, scan_id)
        return direct.dispatch(client, cfg.dispatcher_runtime_arn, url, scan_id)
    except Exception as exc:  # noqa: BLE001 - the verdict turn still runs on what exists
        logger.warning("scan %s: dispatch failed (%s)", scan_id, str(exc)[:120])
        return 0


def _specialist_calls(findings: list[Finding], started) -> list[Call]:
    calls = [
        Call(
            kind=CallKind.SPECIALIST,
            name=f.agent,
            started_at=started,
            duration_ms=f.latency_ms,
            status="ok" if f.status == FindingStatus.OK else f.status.value,
            usage=f.usage,
        )
        for f in findings
    ]
    for finding in findings:
        calls += finding.calls
    return calls


def _complete_unanimous(
    record: ScanRecord,
    token: str,
    started,
    verdict: Verdict,
    findings: list[Finding],
    past,
    dispatch_started,
    breakdown: dict,
    *,
    cfg,
    memory_client,
    bedrock,
) -> None:
    """UNANIMOUS_FAST_PATH: the specialists' unanimous `legitimate`, stored without a verdict
    turn. The caps still run (judge), and the report is still written by the orchestrator
    model, from the stored verdict and findings, so it keeps its notes and disclaimer."""
    scan_id = record.scan_id
    verdict = judge(verdict, findings)
    calls = _specialist_calls(findings, dispatch_started)
    priced = cost.price_scan([f.usage for f in findings])
    completed = utcnow()
    total_ms = ms_between(started, completed)
    stored = store.complete_scan(
        scan_id,
        token,
        verdict=verdict,
        findings=findings,
        calls=calls,
        cost=priced.cost,
        completed_at=completed,
        total_ms=total_ms,
        memory_matches=[{"scan_id": p.scan_id, "summary": p.summary} for p in past],
        report_status=ReportStatus.PENDING,
        unpriced_models=priced.unpriced_models,
    )
    if not stored:
        logger.info(
            "scan already stored by another worker; memory, metrics and log skipped",
            extra={"scan_id": scan_id},
        )
        return
    scan_memory.remember(memory_client, cfg.memory_id, scan_id, record.url, verdict, completed)
    _emit(total_ms, 0, calls)
    logger.info(
        "scan complete",
        extra={
            "scan_id": scan_id,
            "verdict": verdict.verdict.value,
            "total_ms": total_ms,
            "cost_usd": str(priced.cost),
            "report_status": ReportStatus.PENDING.value,
            "orchestration": "direct",
            "fast_path": "unanimous_legitimate",
            **breakdown,
        },
    )
    recovery = build_report_recovery_message(record.url, scan_id, verdict, findings)
    _write_report(
        client=None,
        cfg=cfg,
        record=record,
        token=token,
        verdict=verdict,
        findings=findings,
        calls=calls,
        base_cost=priced.cost,
        run_turn=_converse_turn(bedrock, cfg, [direct.user(recovery)]),
        stop=lambda: None,
    )


def _process_direct(
    record: ScanRecord,
    token: str,
    started,
    *,
    cfg,
    memory=None,
    tools_client=None,
    dispatcher=None,
    bedrock=None,
) -> None:
    """Direct orchestration (worker/direct.py): the precheck and the specialists start
    together, one orchestrator Converse turn gives the verdict, a second one the report."""
    scan_id = record.scan_id
    pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scan")
    try:
        precheck_started = utcnow()
        precheck_future = pool.submit(_precheck, cfg, record.url, scan_id, tools_client)
        dispatch_started = utcnow()
        dispatch_client = dispatcher or clients.dispatcher_runtime()
        dispatch_future = pool.submit(_dispatch_safely, dispatch_client, cfg, record.url, scan_id)
        memory_client = (memory or clients.memory()) if cfg.memory_id else None
        past = scan_memory.recall(memory_client, cfg.memory_id, record.url)
        result = precheck_future.result()
        if result is not None and (result.is_404 or result.is_site_down):
            # The specialists finish on their own; any later attempt clears their Findings and
            # this one never reads them.
            _complete_fast_path(record, token, result, started, precheck_started, [])
            return
        dispatched = dispatch_future.result()
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    dispatch_ms = ms_between(dispatch_started, utcnow())
    findings = load_findings(scan_id, cfg.specialist_model_id)
    unanimous = direct.unanimous_legitimate(findings) if cfg.unanimous_fast_path else None
    if unanimous is not None:
        _complete_unanimous(
            record,
            token,
            started,
            unanimous,
            findings,
            past,
            dispatch_started,
            {"dispatch_ms": dispatch_ms, "dispatched_findings": dispatched},
            cfg=cfg,
            memory_client=memory_client,
            bedrock=bedrock,
        )
        return
    request = direct.verdict_message(
        render_request(record.url, scan_id, [p.summary for p in past]), findings
    )
    synth_started = utcnow()
    try:
        turn, synth_ms, _ = _converse_turn(bedrock, cfg, [direct.user(request)])()
    except aws_retry.ThrottleDeferred as exc:
        store.release_scan(scan_id, token, error="throttled; redelivered", refund_attempt=True)
        raise RetryableScanError(str(exc), delay_seconds=BACKOFF_SECONDS) from exc
    except Exception as exc:  # noqa: BLE001 - retried, then recorded with a correlation id
        ref = log.correlation_ref("converse_verdict", exc)
        _retry_or_fail(
            record,
            token,
            f"The orchestrator could not be invoked. Correlation ID: {ref}",
            total_ms=ms_between(started, utcnow()),
            findings=findings,
        )
        return
    orchestrator_call = Call(
        kind=CallKind.HARNESS,
        name="orchestrator",
        started_at=synth_started,
        duration_ms=synth_ms,
        status="ok",
        usage=turn.usage,
    )
    calls = [orchestrator_call, *_specialist_calls(findings, dispatch_started)]
    breakdown = {
        "orchestration": "direct",
        "dispatch_ms": dispatch_ms,
        "dispatched_findings": dispatched,
        "synth_ms": synth_ms,
    }
    completed = utcnow()
    total_ms = ms_between(started, completed)
    try:
        verdict = judge(parse_verdict(turn.text), findings)
    except VerdictMissing as exc:
        ref = log.correlation_ref("parse_verdict", exc)
        logger.warning(
            "no verdict",
            extra={
                "scan_id": scan_id,
                "reason": str(exc),
                **no_verdict_shape(turn.text),
                **breakdown,
            },
        )
        _emit(total_ms, synth_ms, calls)
        _retry_or_fail(
            record,
            token,
            f"The orchestrator returned no verdict. Correlation ID: {ref}",
            total_ms=total_ms,
            findings=findings,
            calls=calls,
        )
        return
    if verdict.capped_from is not None:
        model = verdict.capped_from
        logger.info(
            "page-not-observed cap changed the verdict",
            extra={
                "scan_id": scan_id,
                "model_verdict": model.verdict.value,
                "model_risk_score": model.risk_score,
                "model_action": model.action.value,
                "verdict": verdict.verdict.value,
                "risk_score": verdict.risk_score,
                "action": verdict.action.value,
            },
        )
    # The report always comes from the second turn here, after the verdict is stored.
    verdict = verdict.model_copy(update={"report_markdown": ""})
    usages = [turn.usage, *(f.usage for f in findings)]
    priced = cost.price_scan(usages)
    stored = store.complete_scan(
        scan_id,
        token,
        verdict=verdict,
        findings=findings,
        calls=calls,
        cost=priced.cost,
        completed_at=completed,
        total_ms=total_ms,
        memory_matches=[{"scan_id": p.scan_id, "summary": p.summary} for p in past],
        report_status=ReportStatus.PENDING,
        unpriced_models=priced.unpriced_models,
    )
    if not stored:
        # Another worker stored this scan and has already remembered, counted and logged it.
        logger.info(
            "scan already stored by another worker; memory, metrics and log skipped",
            extra={"scan_id": scan_id},
        )
        return
    scan_memory.remember(memory_client, cfg.memory_id, scan_id, record.url, verdict, completed)
    _emit(total_ms, synth_ms, calls)
    logger.info(
        "scan complete",
        extra={
            "scan_id": scan_id,
            "verdict": verdict.verdict.value,
            "total_ms": total_ms,
            "harness_ms": synth_ms,
            "cost_usd": str(priced.cost),
            "input_tokens": sum(u.input_tokens for u in usages),
            "output_tokens": sum(u.output_tokens for u in usages),
            "unpriced_models": priced.unpriced_models,
            "memory_hits": len(past),
            "report_status": ReportStatus.PENDING.value,
            **breakdown,
        },
    )
    if stored:
        _write_report(
            client=None,
            cfg=cfg,
            record=record,
            token=token,
            verdict=verdict,
            findings=findings,
            calls=calls,
            base_cost=priced.cost,
            run_turn=_converse_turn(bedrock, cfg, direct.report_messages(request, turn.text)),
            stop=lambda: None,
        )


def process_message(
    message: dict, *, agentcore=None, memory=None, tools_client=None, dispatcher=None, bedrock=None
) -> None:
    cfg = settings()
    scan_id = str(message.get("scan_id", ""))
    token = uuid.uuid4().hex
    try:
        claimed = store.claim_attempt(scan_id, token, utcnow())
    except store.ScanMissing:
        logger.error("scan %s has no row; message dropped", scan_id)
        return
    except store.ClaimUnavailable as exc:
        raise RetryableScanError(str(exc)) from exc
    if claimed is None:
        # Already running or finished. A COMPLETE scan whose report is PENDING and whose
        # worker is gone is the one case that still has work to do.
        try:
            _resume_report(scan_id, agentcore, bedrock)
        except (ClientError, BotoCoreError):
            logger.exception("scan %s: could not check for a pending report", scan_id)
        else:
            logger.info("scan %s already claimed or finished; duplicate message handled", scan_id)
        return
    record, claim_number = claimed
    started = record.started_at or utcnow()
    try:
        cleared = clear_findings(scan_id)
    except (ClientError, BotoCoreError, RuntimeError) as exc:
        ref = log.correlation_ref("clear_findings", exc)
        _retry_or_fail(
            record, token, f"Earlier findings could not be cleared. Correlation ID: {ref}"
        )
        return
    if cleared:
        logger.info("scan %s: cleared %d findings from an earlier attempt", scan_id, cleared)
    if cfg.direct_orchestration:
        _process_direct(
            record,
            token,
            started,
            cfg=cfg,
            memory=memory,
            tools_client=tools_client,
            dispatcher=dispatcher,
            bedrock=bedrock,
        )
        return

    precheck_started = utcnow()
    result = _precheck(cfg, record.url, scan_id, tools_client)
    if result is not None and (result.is_404 or result.is_site_down):
        _complete_fast_path(record, token, result, started, precheck_started, [])
        return

    client = agentcore or clients.agentcore()
    memory_client = (memory or clients.memory()) if cfg.memory_id else None
    # Read before the harness call; a failed read returns [] and the scan runs without it.
    past = scan_memory.recall(memory_client, cfg.memory_id, record.url)
    past_scans = [p.summary for p in past]
    # A fresh session per claim: an attempt never inherits an earlier attempt's context.
    session_id = aws_retry.scan_session_id(scan_id, claim_number)
    # The harness call starts here, after the precheck and the memory read, not at the claim.
    harness_started = utcnow()
    try:
        outcome, invoke_ms, harness_ms = _turn(
            client, cfg, session_id, render_request(record.url, scan_id, past_scans), scan_id
        )
    except aws_retry.ThrottleDeferred as exc:
        # Throttled with no time for another call: nothing ran, so no attempt is spent.
        # SQS maxReceiveCount (5) still bounds this, then the DLQ sweeper marks it FAILED.
        store.release_scan(scan_id, token, error="throttled; redelivered", refund_attempt=True)
        raise RetryableScanError(str(exc), delay_seconds=BACKOFF_SECONDS) from exc
    except Exception as exc:  # noqa: BLE001 - retried, then recorded with a correlation id
        ref = log.correlation_ref("invoke_harness", exc)
        aws_retry.stop_harness_session(client, session_id, cfg.harness_arn)
        _retry_or_fail(
            record,
            token,
            f"The orchestrator could not be invoked. Correlation ID: {ref}",
            total_ms=ms_between(started, utcnow()),
        )
        return

    findings = load_findings(scan_id, cfg.specialist_model_id)
    harness_call = Call(
        kind=CallKind.HARNESS,
        name="orchestrator",
        started_at=harness_started,
        duration_ms=harness_ms,
        status="ok",
        usage=outcome.usage,
    )
    calls = _collect_calls(harness_call, outcome, findings)
    breakdown = harness_breakdown(harness_ms, invoke_ms, outcome)
    completed = utcnow()
    total_ms = ms_between(started, completed)
    try:
        verdict = judge(parse_verdict(outcome.text), findings)
    except VerdictMissing as exc:
        aws_retry.stop_harness_session(client, session_id, cfg.harness_arn)
        ref = log.correlation_ref("parse_verdict", exc)
        # The shape of the answer is the only clue to why turn 1 had no verdict JSON (empty
        # answer, prose, truncated or broken JSON); the stream is gone after this. Never the
        # text itself: it can echo the submitted URL or the attacker's page.
        logger.warning(
            "no verdict",
            extra={
                "scan_id": scan_id,
                "reason": str(exc),
                **no_verdict_shape(outcome.text),
                **breakdown,
            },
        )
        _emit(total_ms, harness_ms, calls, breakdown)
        _retry_or_fail(
            record,
            token,
            f"The orchestrator returned no verdict. Correlation ID: {ref}",
            total_ms=total_ms,
            findings=findings,
            calls=calls,
        )
        return
    if verdict.capped_from is not None:
        model = verdict.capped_from
        logger.info(
            "page-not-observed cap changed the verdict",
            extra={
                "scan_id": scan_id,
                "model_verdict": model.verdict.value,
                "model_risk_score": model.risk_score,
                "model_action": model.action.value,
                "verdict": verdict.verdict.value,
                "risk_score": verdict.risk_score,
                "action": verdict.action.value,
            },
        )
    # An orchestrator that still answers in one turn (older prompt, or a scan in flight
    # during the release) sent the whole report: keep the single-turn behaviour, no turn 2.
    has_report = bool(verdict.report_markdown.strip())
    if has_report:
        report = report_with_note(verdict.report_markdown, verdict, findings)
        verdict, output_events = guardrails.screen_report(
            verdict.model_copy(update={"report_markdown": report})
        )
        # Server-side and after the guardrail, so neither the model nor a withheld report drops it.
        verdict = verdict.model_copy(
            update={"report_markdown": with_disclaimer_markdown(verdict.report_markdown)}
        )
        if output_events:
            store.add_guardrail_events(scan_id, output_events)
        report_status = ReportStatus.READY
    else:
        report_status = ReportStatus.PENDING
    usages = [outcome.usage, *(f.usage for f in findings)]
    priced = cost.price_scan(usages)
    scan_cost = priced.cost
    stored = store.complete_scan(
        scan_id,
        token,
        verdict=verdict,
        findings=findings,
        calls=calls,
        cost=scan_cost,
        completed_at=completed,
        total_ms=total_ms,
        memory_matches=[{"scan_id": p.scan_id, "summary": p.summary} for p in past],
        report_status=report_status,
        unpriced_models=priced.unpriced_models,
    )
    if report_status == ReportStatus.READY or not stored:
        aws_retry.stop_harness_session(client, session_id, cfg.harness_arn)
    # After the verdict is stored, so a failed or slow write can never cost the scan.
    scan_memory.remember(memory_client, cfg.memory_id, scan_id, record.url, verdict, completed)
    _emit(total_ms, harness_ms, calls, breakdown)
    logger.info(
        "scan complete",
        extra={
            "scan_id": scan_id,
            "verdict": verdict.verdict.value,
            "total_ms": total_ms,
            "harness_ms": harness_ms,
            "cycles": outcome.cycles,
            "cost_usd": str(scan_cost),
            "input_tokens": sum(u.input_tokens for u in usages),
            "output_tokens": sum(u.output_tokens for u in usages),
            "unpriced_models": priced.unpriced_models,
            "memory_hits": len(past_scans),
            "report_status": report_status.value,
            **breakdown,
        },
    )
    if report_status == ReportStatus.PENDING and stored:
        _write_report(
            client=client,
            cfg=cfg,
            record=record,
            token=token,
            verdict=verdict,
            findings=findings,
            calls=calls,
            base_cost=scan_cost,
            session_id=session_id,
            message=REPORT_FOLLOWUP_MESSAGE,
        )
