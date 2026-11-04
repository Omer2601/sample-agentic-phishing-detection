# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Batch path: CSV upload -> split_csv -> SQS -> worker -> harness; scans stream -> stats
aggregator; scan DLQ -> dead-letter sweeper."""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_cloudwatch_actions as cw_actions
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_lambda_destinations as destinations
from aws_cdk import aws_lambda_event_sources as sources
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_notifications as s3n
from aws_cdk import aws_sqs as sqs
from constructs import Construct

from phish_infra.common import bedrock_invoke_statements, python_function, stack_output
from phish_infra.config import AppConfig
from phish_infra.constructs.agents import AgentsLayer
from phish_infra.constructs.data import DataLayer
from phish_infra.constructs.guardrails import Guardrails
from phish_infra.constructs.memory import ScanMemory

WORKER_TIMEOUT_SECONDS = 300
# Above the worker's own 3 attempts (MAX_SCAN_ATTEMPTS), so only a Lambda that kept crashing or
# timing out is dead-lettered; the sweeper then marks the scan FAILED with a reason.
MAX_RECEIVE_COUNT = 5
SWEEPER_TIMEOUT_SECONDS = 60


def backend_environment(cfg: AppConfig, data: DataLayer, agents: AgentsLayer) -> dict[str, str]:
    return {
        "SCANS_TABLE": data.scans_table.table_name,
        "BATCHES_TABLE": data.batches_table.table_name,
        "STATS_TABLE": data.stats_table.table_name,
        "UPLOAD_BUCKET": data.upload_bucket.bucket_name,
        "ARTIFACTS_BUCKET": data.artifacts_bucket.bucket_name,
        "HARNESS_ARN": agents.harness_arn,
        "ORCHESTRATOR_MODEL_ID": cfg.orchestrator_model,
        "SPECIALIST_MODEL_ID": cfg.specialist_model,
        "UI_BATCH_MAX": "200",
        "API_BATCH_MAX": "1000",
        "JSON_BATCH_MAX": "50",
        "RETENTION_DAYS": str(cfg.retention_days),
        # The worker sends a per-invocation model override when effort or caching is on.
        "ORCHESTRATOR_PROMPT_CACHE": "1" if cfg.orchestrator_prompt_cache else "0",
        **({"ORCHESTRATOR_EFFORT": cfg.orchestrator_effort} if cfg.orchestrator_effort else {}),
        **(
            {"HARNESS_MAX_TOKENS": str(cfg.harness_max_tokens)}
            if cfg.orchestrator_effort or cfg.orchestrator_prompt_cache
            else {}
        ),
    }


class ScanPipeline(Construct):
    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        cfg: AppConfig,
        data: DataLayer,
        guardrails: Guardrails,
        agents: AgentsLayer,
        backend_code: lambda_.Code,
        memory: ScanMemory | None = None,
    ) -> None:
        super().__init__(scope, id)
        name, env = cfg.app_name, cfg.environment

        def queue(id_: str, queue_name: str, **extra) -> sqs.Queue:
            return sqs.Queue(
                self,
                id_,
                queue_name=f"{name}-{queue_name}-{env}",
                encryption=sqs.QueueEncryption.KMS,
                encryption_master_key=data.key,
                enforce_ssl=True,
                removal_policy=cfg.removal_policy,
                **extra,
            )

        fourteen_days = cdk.Duration.days(14)
        # Consumed by the dead-letter sweeper (60 s timeout): 6x its timeout, per Lambda guidance.
        self.dlq = queue(
            "Dlq",
            "scan-dlq",
            retention_period=fourteen_days,
            visibility_timeout=cdk.Duration.seconds(6 * SWEEPER_TIMEOUT_SECONDS),
        )
        # Own DLQ: stream batch records are not scan messages and must not reach the sweeper.
        self.stream_dlq = queue("StreamDlq", "stats-stream-dlq", retention_period=fourteen_days)
        # Splitter invocations that failed every async attempt (the S3 event is lost otherwise).
        # Nothing consumes it: the requeue sweeper already marks a batch still awaiting_upload
        # past its window FAILED, so this queue plus its alarm is the operator's evidence.
        self.batch_dlq = queue("BatchDlq", "batch-dlq", retention_period=fourteen_days)
        self.queue = queue(
            "Queue",
            "scan-queue",
            visibility_timeout=cdk.Duration.seconds(6 * WORKER_TIMEOUT_SECONDS),
            retention_period=cdk.Duration.days(4),
            dead_letter_queue=sqs.DeadLetterQueue(
                queue=self.dlq, max_receive_count=MAX_RECEIVE_COUNT
            ),
        )
        base_env = {
            **backend_environment(cfg, data, agents),
            "SCAN_QUEUE_URL": self.queue.queue_url,
        }

        worker_env = {
            **base_env,
            "GUARDRAIL_OUTPUT_ID": guardrails.output_id,
            "GUARDRAIL_OUTPUT_VERSION": guardrails.output_version,
            # Absent when -c episodicMemory=false: the worker then skips memory entirely.
            **({"MEMORY_ID": memory.memory_id} if memory else {}),
            # The worker calls precheck_url on the tools Runtime itself (404 and site-down fast
            # path), not through a Gateway.
            "TOOLS_RUNTIME_ARN": agents.tools_runtime.agent_runtime_arn,
            # -c directOrchestration: dispatcher plus two Converse calls instead of the Harness.
            **(
                {
                    "ORCHESTRATION_MODE": "direct",
                    "DISPATCHER_RUNTIME_ARN": agents.dispatcher.agent_runtime_arn,
                    **({"UNANIMOUS_FAST_PATH": "1"} if cfg.unanimous_fast_path else {}),
                    **(
                        {
                            "DIRECT_SPECIALISTS": "1",
                            **{
                                f"{name.upper()}_RUNTIME_ARN": runtime.agent_runtime_arn
                                for name, runtime in agents.runtimes.items()
                            },
                        }
                        if cfg.direct_specialists
                        else {}
                    ),
                }
                if cfg.direct_orchestration
                else {}
            ),
            # -c directTools: the precheck opens the scan's one shared tools session.
            **({"TOOLS_SESSION_PER_SCAN": "1"} if cfg.direct_tools else {}),
        }

        # ── Worker: one URL per invocation, one harness call per URL ─────────
        self.worker = python_function(
            self,
            "Worker",
            cfg=cfg,
            key=data.key,
            code=backend_code,
            handler="phish_backend.worker.run_scan.handler",
            description="Runs one scan: invokes the orchestrator harness and stores the verdict",
            environment=worker_env,
            timeout=cdk.Duration.seconds(WORKER_TIMEOUT_SECONDS),
            memory_mb=512,
        )
        # The event source grant includes ChangeMessageVisibility, which the worker uses to back
        # off a transient failure (30 s, then 60 s).
        self.worker.add_event_source(
            sources.SqsEventSource(
                self.queue,
                batch_size=1,
                max_concurrency=cfg.scan_concurrency,
                report_batch_item_failures=True,
            )
        )
        data.scans_table.grant(self.worker, "dynamodb:GetItem", "dynamodb:UpdateItem")
        data.batches_table.grant(self.worker, "dynamodb:GetItem", "dynamodb:UpdateItem")
        self.worker.add_to_role_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject"],
                resources=[data.artifacts_bucket.arn_for_objects("scans/*")],
            )
        )
        self.worker.add_to_role_policy(
            iam.PolicyStatement(
                actions=["bedrock:ApplyGuardrail"], resources=[guardrails.output_arn]
            )
        )
        # Each attempt clears the previous attempt's findings, so a retry never reads stale ones.
        self.worker.add_to_role_policy(
            iam.PolicyStatement(
                actions=["s3:ListBucket"],
                resources=[data.artifacts_bucket.bucket_arn],
                conditions={"StringLike": {"s3:prefix": "scans/*"}},
            )
        )
        self.worker.add_to_role_policy(
            iam.PolicyStatement(
                actions=["s3:DeleteObject"],
                resources=[data.artifacts_bucket.arn_for_objects("scans/*/findings/*")],
            )
        )
        data.key.grant_encrypt_decrypt(self.worker)
        agents.grant_invoke_harness(self.worker)
        agents.grant_invoke_tools(self.worker)
        if cfg.direct_orchestration:
            # The Harness grant stays, so scans already in flight can finish and a redeploy
            # without the flag rolls back cleanly.
            agents.grant_invoke_dispatcher(self.worker)
            if cfg.direct_specialists:
                agents.grant_invoke_specialists(self.worker)
            for statement in bedrock_invoke_statements(self, [cfg.orchestrator_model]):
                self.worker.add_to_role_policy(statement)
        if memory:
            memory.grant_worker(self.worker)

        # ── Requeue sweeper: re-sends scans whose claim or message went missing ─
        self.requeue_stuck = python_function(
            self,
            "RequeueStuck",
            cfg=cfg,
            key=data.key,
            code=backend_code,
            handler="phish_backend.worker.requeue_stuck.handler",
            description="Every 5 minutes: re-enqueues scans stuck past their claim lease",
            environment=worker_env,
            timeout=cdk.Duration.seconds(120),
            memory_mb=256,
        )
        # Scans: a Query on the status index, never a table Scan. Batches: a filtered Scan
        # for uploads that never arrived (one row per batch, not per URL).
        data.scans_table.grant(self.requeue_stuck, "dynamodb:Query", "dynamodb:UpdateItem")
        data.batches_table.grant(
            self.requeue_stuck, "dynamodb:Query", "dynamodb:Scan", "dynamodb:UpdateItem"
        )
        self.queue.grant_send_messages(self.requeue_stuck)
        data.key.grant_encrypt_decrypt(self.requeue_stuck)
        events.Rule(
            self,
            "RequeueStuckSchedule",
            description="Runs the stuck-scan requeue sweeper",
            schedule=events.Schedule.rate(cdk.Duration.minutes(5)),
            targets=[targets.LambdaFunction(self.requeue_stuck, retry_attempts=2)],
        )

        # ── Splitter: CSV in S3 -> one PENDING row and one SQS message per URL ─
        self.splitter = python_function(
            self,
            "Splitter",
            cfg=cfg,
            key=data.key,
            code=backend_code,
            handler="phish_backend.batch.split_csv.handler",
            description="Parses an uploaded CSV and enqueues one scan per URL",
            environment={
                **base_env,
                "GUARDRAIL_INPUT_ID": guardrails.input_id,
                "GUARDRAIL_INPUT_VERSION": guardrails.input_version,
            },
            timeout=cdk.Duration.seconds(120),
            memory_mb=512,
        )
        # S3 invokes asynchronously: two retries, then the event goes to the batch DLQ.
        self.splitter.configure_async_invoke(
            retry_attempts=2, on_failure=destinations.SqsDestination(self.batch_dlq)
        )
        # Every CSV row passes the same input guardrail as a URL submitted to the API.
        self.splitter.add_to_role_policy(
            iam.PolicyStatement(
                actions=["bedrock:ApplyGuardrail"], resources=[guardrails.input_arn]
            )
        )
        data.upload_bucket.add_event_notification(
            s3.EventType.OBJECT_CREATED,
            s3n.LambdaDestination(self.splitter),
            s3.NotificationKeyFilter(prefix="uploads/", suffix=".csv"),
        )
        # HeadObject authorizes with s3:GetObject.
        self.splitter.add_to_role_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject"],
                resources=[data.upload_bucket.arn_for_objects("uploads/*")],
            )
        )
        data.scans_table.grant(
            self.splitter, "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:BatchWriteItem"
        )
        data.batches_table.grant(self.splitter, "dynamodb:GetItem", "dynamodb:UpdateItem")
        self.queue.grant_send_messages(self.splitter)
        data.key.grant_encrypt_decrypt(self.splitter)

        # ── Aggregator: scans stream -> per-owner stats and batch counters ────
        self.aggregator = python_function(
            self,
            "Aggregator",
            cfg=cfg,
            key=data.key,
            code=backend_code,
            handler="phish_backend.stats.aggregate.handler",
            description="Folds scan transitions into batch counters and per-owner stats",
            environment=base_env,
            timeout=cdk.Duration.seconds(60),
            memory_mb=256,
        )
        self.aggregator.add_event_source(
            sources.DynamoEventSource(
                data.scans_table,
                starting_position=lambda_.StartingPosition.LATEST,
                batch_size=25,
                bisect_batch_on_error=True,
                retry_attempts=3,
                report_batch_item_failures=True,
                on_failure=sources.SqsDlq(self.stream_dlq),
            )
        )
        # Counters and the idempotency marker are written in one TransactWriteItems call; a retry
        # (FAILED to PENDING) deletes the markers and reverses the counters the same way.
        data.stats_table.grant(
            self.aggregator,
            "dynamodb:GetItem",
            "dynamodb:UpdateItem",
            "dynamodb:PutItem",
            "dynamodb:DeleteItem",
            "dynamodb:ConditionCheckItem",
        )
        data.batches_table.grant(self.aggregator, "dynamodb:GetItem", "dynamodb:UpdateItem")
        data.key.grant_encrypt_decrypt(self.aggregator)

        # ── Dead-letter sweeper: no scan is dropped ─────────────────────────
        self.dead_letter = python_function(
            self,
            "DeadLetter",
            cfg=cfg,
            key=data.key,
            code=backend_code,
            handler="phish_backend.worker.dead_letter.handler",
            description="Marks scans that exhausted SQS redelivery as FAILED with a reason",
            environment=base_env,
            timeout=cdk.Duration.seconds(SWEEPER_TIMEOUT_SECONDS),
            memory_mb=256,
        )
        self.dead_letter.add_event_source(
            sources.SqsEventSource(self.dlq, batch_size=10, report_batch_item_failures=True)
        )
        data.scans_table.grant(self.dead_letter, "dynamodb:GetItem", "dynamodb:UpdateItem")
        data.key.grant_encrypt_decrypt(self.dead_letter)

        # ── Alarms ──────────────────────────────────────────────────────────
        action = cw_actions.SnsAction(data.alarm_topic)

        def alarm(
            id_: str,
            alarm_name: str,
            description: str,
            metric: cloudwatch.IMetric,
            threshold: float,
        ) -> None:
            cloudwatch.Alarm(
                self,
                id_,
                alarm_name=f"{name}-{alarm_name}-{env}",
                alarm_description=description,
                metric=metric,
                threshold=threshold,
                evaluation_periods=1,
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
            ).add_alarm_action(action)

        five = cdk.Duration.minutes(5)
        alarm(
            "DlqNotEmpty",
            "scan-dlq-not-empty",
            "A scan exhausted SQS redelivery; the sweeper marked it FAILED. Check worker errors.",
            self.dlq.metric_approximate_number_of_messages_visible(
                period=five, statistic="Maximum"
            ),
            0,
        )
        alarm(
            "StreamDlqNotEmpty",
            "stats-stream-dlq-not-empty",
            "Stats aggregation failed for a stream batch: batch counters or Insights may lag.",
            self.stream_dlq.metric_approximate_number_of_messages_visible(
                period=five, statistic="Maximum"
            ),
            0,
        )
        alarm(
            "BatchDlqNotEmpty",
            "batch-dlq-not-empty",
            "A CSV upload failed splitting after retries; the sweeper marks its batch FAILED.",
            self.batch_dlq.metric_approximate_number_of_messages_visible(
                period=five, statistic="Maximum"
            ),
            0,
        )
        alarm(
            "QueueBacklog",
            "scan-queue-backlog",
            "Oldest scan waited over 45 minutes: worker stalled or submissions outrun concurrency.",
            self.queue.metric_approximate_age_of_oldest_message(period=five, statistic="Maximum"),
            cdk.Duration.minutes(45).to_seconds(),
        )
        alarm(
            "WorkerErrors",
            "worker-errors",
            "Worker errors above threshold: scans are failing.",
            self.worker.metric_errors(period=five),
            10,
        )
        alarm(
            "WorkerThrottles",
            "worker-throttles",
            "Worker throttled: concurrency exhausted.",
            self.worker.metric_throttles(period=cdk.Duration.minutes(1)),
            5,
        )

        stack_output(self, "ScanQueueUrl", self.queue.queue_url, "Scan work queue")
        stack_output(self, "ScanDlqUrl", self.dlq.queue_url, "Scans that exhausted SQS redelivery")
