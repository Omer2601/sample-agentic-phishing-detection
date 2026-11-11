# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Evaluate each of the four agents independently against a labelled URL set.

Specialists are called directly on their Runtimes (MCP tools/call); the orchestrator is
called through the harness. Scores are computed per agent so a regression in one
specialist is visible even when the orchestrator still gets the final verdict right.

Usage:
  AWS_PROFILE=<profile> uv run --package phish-agents \
    python eval/evaluate_agents.py --agent all --limit 10
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import statistics
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import boto3
from botocore.config import Config

from phish_contracts.models import Finding, build_orchestrator_message, extract_verdict

logger = logging.getLogger("evaluate_agents")

HERE = Path(__file__).resolve().parent
OUTPUT_KEYS = {
    "url_analyst": "UrlAnalystRuntimeArn",
    "brand_visual": "BrandVisualRuntimeArn",
    "code_analyst": "CodeAnalystRuntimeArn",
    "orchestrator": "OrchestratorHarnessArn",
}


def call_specialist(client, runtime_arn: str, url: str, scan_id: str) -> Finding:
    """One MCP tools/call to a specialist Runtime: the stateless JSON exchange it serves."""
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "analyze", "arguments": {"url": url, "scan_id": scan_id}},
    }
    response = client.invoke_agent_runtime(
        agentRuntimeArn=runtime_arn,
        runtimeSessionId=f"{scan_id}-{uuid.uuid4().hex}",
        payload=json.dumps(request),
        contentType="application/json",
        accept="application/json, text/event-stream",
    )
    body = json.loads(response["response"].read())
    return Finding.model_validate_json(body["result"]["content"][0]["text"])


def load_dataset(path: Path) -> list[tuple[str, str]]:
    rows = []
    with path.open(newline="") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#") or row[0] == "url":
                continue
            rows.append((row[0].strip(), row[1].strip().lower()))
    return rows


def to_prediction(verdict: str, suspicious_as: str) -> str | None:
    v = verdict.lower()
    if v == "suspicious":
        return suspicious_as
    return v if v in {"phishing", "legitimate"} else None


def score(rows: list[dict]) -> dict:
    tp = sum(r["label"] == "phishing" and r["prediction"] == "phishing" for r in rows)
    fn = sum(r["label"] == "phishing" and r["prediction"] == "legitimate" for r in rows)
    tn = sum(r["label"] == "legitimate" and r["prediction"] == "legitimate" for r in rows)
    fp = sum(r["label"] == "legitimate" and r["prediction"] == "phishing" for r in rows)
    errors = sum(r["prediction"] is None for r in rows)

    def ratio(a: int, b: int) -> float | None:
        return round(a / b, 3) if b else None

    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 3) if precision and recall else None
    latencies = [r["latency_ms"] for r in rows]
    return {
        "tp": tp,
        "fn": fn,
        "tn": tn,
        "fp": fp,
        "errors": errors,
        "accuracy": ratio(tp + tn, tp + tn + fp + fn),
        "precision": precision,
        "recall": recall,
        "fpr": ratio(fp, fp + tn),
        "f1": f1,
        "p50_ms": int(statistics.median(latencies)) if latencies else None,
    }


def stack_outputs(session, stack_name: str, region: str) -> dict[str, str]:
    stack = session.client("cloudformation", region_name=region).describe_stacks(
        StackName=stack_name
    )["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def agentcore_client(session, region: str):
    # One attempt: retrying a timed-out invoke would re-run a non-idempotent scan and
    # double its cost. The harness runs a full scan, so the read timeout is long.
    return session.client(
        "bedrock-agentcore",
        region_name=region,
        config=Config(read_timeout=300, connect_timeout=10, retries={"total_max_attempts": 1}),
    )


def run_orchestrator(client, harness_arn: str, url: str, scan_id: str) -> str:
    text = []
    response = client.invoke_harness(
        harnessArn=harness_arn,
        runtimeSessionId=f"{scan_id}-{uuid.uuid4().hex}",
        messages=[
            {"role": "user", "content": [{"text": build_orchestrator_message(url, scan_id)}]}
        ],
    )
    for event in response.get("stream", []):
        delta = event.get("contentBlockDelta", {}).get("delta", {})
        if isinstance(delta.get("text"), str):
            text.append(delta["text"])
    return extract_verdict("".join(text)).verdict.value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dataset", type=Path, default=HERE / "data" / "committed_sample.csv")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--agent", choices=["all", *OUTPUT_KEYS], default="all")
    parser.add_argument("--stack", default="PhishTriageAgentic")
    parser.add_argument(
        "--region", default=None, help="defaults to the session region (AWS_REGION or profile)"
    )
    parser.add_argument("--suspicious-as", choices=["phishing", "legitimate"], default="phishing")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    session = boto3.Session()
    region = args.region or session.region_name
    if not region:
        parser.error("no region: pass --region or set AWS_REGION")
    outputs = stack_outputs(session, args.stack, region)
    client = agentcore_client(session, region)
    dataset = load_dataset(args.dataset)[: args.limit]
    results: dict[str, list[dict]] = {}
    for agent in list(OUTPUT_KEYS) if args.agent == "all" else [args.agent]:
        arn = outputs[OUTPUT_KEYS[agent]]
        rows = []
        for url, label in dataset:
            scan_id = f"eval-{uuid.uuid4().hex[:16]}"
            t0 = time.monotonic()
            try:
                if agent == "orchestrator":
                    verdict = run_orchestrator(client, arn, url, scan_id)
                else:
                    verdict = call_specialist(client, arn, url, scan_id).verdict.value
            except Exception as exc:  # noqa: BLE001 - an agent failure is a scored error, not a crash
                logger.info("%s %s failed: %s", agent, url, type(exc).__name__)
                verdict = "error"
            rows.append(
                {
                    "url": url,
                    "label": label,
                    "verdict": verdict,
                    "prediction": to_prediction(verdict, args.suspicious_as),
                    "latency_ms": int((time.monotonic() - t0) * 1000),
                }
            )
        results[agent] = rows

    report = {agent: score(rows) for agent, rows in results.items()}
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out = HERE / "results" / f"{stamp}.json"
    out.write_text(json.dumps({"scores": report, "rows": results}, indent=2))
    logger.info("| agent | accuracy | precision | recall | f1 | errors | p50 ms |")
    logger.info("|---|---|---|---|---|---|---|")
    for agent, s in report.items():
        cells = [s[k] for k in ("accuracy", "precision", "recall", "f1", "errors", "p50_ms")]
        logger.info("| %s | %s |", agent, " | ".join(str(c) for c in cells))
    logger.info("\nwrote %s", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
