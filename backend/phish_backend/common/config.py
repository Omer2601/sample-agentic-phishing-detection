# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Runtime configuration, read once from the Lambda environment."""

import os
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Settings:
    scans_table: str
    batches_table: str
    stats_table: str
    scan_queue_url: str
    upload_bucket: str
    artifacts_bucket: str
    harness_arn: str
    orchestrator_model_id: str
    specialist_model_id: str
    proxy_role_arn: str
    region: str
    ui_batch_max: int
    api_batch_max: int
    json_batch_max: int
    retention_days: int
    guardrail_input_id: str
    guardrail_input_version: str
    guardrail_output_id: str
    guardrail_output_version: str
    orchestrator_effort: str = ""
    # Bedrock automatic prompt caching on both Harness turns of a scan (verdict, then report).
    orchestrator_prompt_cache: bool = True
    # The web console origin, for links from the batch HTML report back to each scan.
    console_url: str = ""
    harness_max_tokens: int = 8192
    # Empty: episodic memory is off (-c episodicMemory=false) and the worker skips it.
    memory_id: str = ""
    # Tools MCP runtime (precheck_url). Empty: the HTTP 404 fast path is off.
    tools_runtime_arn: str = ""
    # TOOLS_SESSION_PER_SCAN=1 (-c directTools): the precheck uses the scan's shared tools session.
    tools_session_per_scan: bool = False
    # "direct": the worker runs the dispatcher alongside the precheck and asks the orchestrator
    # model for the verdict in one Converse call (worker/direct.py). Anything else, or no
    # dispatcher ARN: the harness path. Off unless the stack sets it (-c directOrchestration).
    orchestration_mode: str = "harness"
    dispatcher_runtime_arn: str = ""
    # UNANIMOUS_FAST_PATH=1 (direct orchestration only): no verdict turn when all three
    # specialists agree the page is legitimate with high confidence (direct.unanimous_legitimate).
    unanimous_fast_path: bool = False
    # DIRECT_SPECIALISTS=1 (direct orchestration only): the worker invokes the three specialist
    # Runtimes itself instead of the dispatcher. Their ARNs, by specialist name.
    direct_specialists_flag: bool = False
    specialist_runtime_arns: tuple[tuple[str, str], ...] = ()
    # POST /scan Idempotency-Key claims. Empty: a request with the header gets 501.
    idempotency_table: str = ""
    # POST /scan reuse of the caller's own recent scan of the same URL (-c scanDedup=true).
    scan_dedup_enabled: bool = False

    @property
    def direct_orchestration(self) -> bool:
        return self.orchestration_mode == "direct" and bool(self.dispatcher_runtime_arn)

    @property
    def direct_specialists(self) -> bool:
        arns = dict(self.specialist_runtime_arns)
        return (
            self.direct_orchestration
            and self.direct_specialists_flag
            and all(arns.get(a) for a in ("url_analyst", "brand_visual", "code_analyst"))
        )


@lru_cache(maxsize=1)
def settings() -> Settings:
    env = os.environ
    return Settings(
        scans_table=env.get("SCANS_TABLE", ""),
        batches_table=env.get("BATCHES_TABLE", ""),
        stats_table=env.get("STATS_TABLE", ""),
        scan_queue_url=env.get("SCAN_QUEUE_URL", ""),
        upload_bucket=env.get("UPLOAD_BUCKET", ""),
        artifacts_bucket=env.get("ARTIFACTS_BUCKET", ""),
        harness_arn=env.get("HARNESS_ARN", ""),
        orchestrator_model_id=env.get("ORCHESTRATOR_MODEL_ID", "us.anthropic.claude-opus-5-5"),
        specialist_model_id=env.get("SPECIALIST_MODEL_ID", "global.anthropic.claude-sonnet-5-5"),
        proxy_role_arn=env.get("PROXY_ROLE_ARN", ""),
        region=env.get("AWS_REGION", ""),
        ui_batch_max=int(env.get("UI_BATCH_MAX", "200")),
        api_batch_max=int(env.get("API_BATCH_MAX", "1000")),
        json_batch_max=int(env.get("JSON_BATCH_MAX", "50")),
        retention_days=int(env.get("RETENTION_DAYS", "90")),
        guardrail_input_id=env.get("GUARDRAIL_INPUT_ID", ""),
        guardrail_input_version=env.get("GUARDRAIL_INPUT_VERSION", ""),
        guardrail_output_id=env.get("GUARDRAIL_OUTPUT_ID", ""),
        guardrail_output_version=env.get("GUARDRAIL_OUTPUT_VERSION", ""),
        orchestrator_effort=env.get("ORCHESTRATOR_EFFORT", "").strip().lower(),
        orchestrator_prompt_cache=env.get("ORCHESTRATOR_PROMPT_CACHE", "1").strip().lower()
        not in {"0", "false", "off", "no"},
        console_url=env.get("CONSOLE_URL", ""),
        harness_max_tokens=int(env.get("HARNESS_MAX_TOKENS", "8192")),
        memory_id=env.get("MEMORY_ID", "").strip(),
        tools_runtime_arn=env.get("TOOLS_RUNTIME_ARN", "").strip(),
        tools_session_per_scan=env.get("TOOLS_SESSION_PER_SCAN", "").strip() == "1",
        orchestration_mode=env.get("ORCHESTRATION_MODE", "harness").strip().lower(),
        dispatcher_runtime_arn=env.get("DISPATCHER_RUNTIME_ARN", "").strip(),
        unanimous_fast_path=env.get("UNANIMOUS_FAST_PATH", "").strip() == "1",
        direct_specialists_flag=env.get("DIRECT_SPECIALISTS", "").strip() == "1",
        specialist_runtime_arns=tuple(
            (agent, env.get(f"{agent.upper()}_RUNTIME_ARN", "").strip())
            for agent in ("url_analyst", "brand_visual", "code_analyst")
        ),
        idempotency_table=env.get("IDEMPOTENCY_TABLE", "").strip(),
        scan_dedup_enabled=env.get("SCAN_DEDUP_ENABLED", "").strip() == "1",
    )
