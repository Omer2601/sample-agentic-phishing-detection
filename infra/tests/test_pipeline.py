# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import aws_cdk as cdk
import pytest
from aws_cdk import aws_lambda as lambda_
from aws_cdk.assertions import Match, Template

from phish_infra.config import load_config
from phish_infra.constructs.agents import AgentsLayer
from phish_infra.constructs.data import DataLayer
from phish_infra.constructs.guardrails import Guardrails
from phish_infra.constructs.pipeline import MAX_RECEIVE_COUNT, WORKER_TIMEOUT_SECONDS, ScanPipeline


@pytest.fixture(scope="module")
def t(harness_context, test_env, tmp_path_factory):
    app = cdk.App(context=harness_context)
    stack = cdk.Stack(app, "S", env=test_env)
    cfg = load_config(app.node)
    data = DataLayer(stack, "Data", cfg=cfg)
    agents = AgentsLayer(
        stack, "Agents", cfg=cfg, key=data.key, artifacts_bucket=data.artifacts_bucket
    )
    code = lambda_.Code.from_asset(str(tmp_path_factory.mktemp("code")))
    ScanPipeline(
        stack,
        "Pipeline",
        cfg=cfg,
        data=data,
        guardrails=Guardrails(stack, "G", cfg=cfg),
        agents=agents,
        backend_code=code,
    )
    return Template.from_stack(stack)


def function(t, handler):
    (fn,) = t.find_resources("AWS::Lambda::Function", {"Properties": {"Handler": handler}}).values()
    return fn


def role_policy_text(t, handler):
    role = function(t, handler)["Properties"]["Role"]["Fn::GetAtt"][0]
    return str(
        [
            p
            for p in t.find_resources("AWS::IAM::Policy").values()
            if {"Ref": role} in p["Properties"]["Roles"]
        ]
    )


def test_standard_queue_with_dlq(t):
    t.has_resource_properties(
        "AWS::SQS::Queue",
        {
            "QueueName": "phish-scan-queue-dev",
            "FifoQueue": Match.absent(),
            "RedrivePolicy": Match.object_like({"maxReceiveCount": MAX_RECEIVE_COUNT}),
            # Six times the worker timeout, the Lambda guidance for SQS event sources.
            "VisibilityTimeout": 6 * WORKER_TIMEOUT_SECONDS,
            "KmsMasterKeyId": Match.any_value(),
        },
    )
    assert MAX_RECEIVE_COUNT == 5 and WORKER_TIMEOUT_SECONDS == 300
    for name in ("phish-scan-dlq-dev", "phish-stats-stream-dlq-dev"):
        t.has_resource_properties(
            "AWS::SQS::Queue",
            {
                "QueueName": name,
                "MessageRetentionPeriod": 1209600,
                "KmsMasterKeyId": Match.any_value(),
            },
        )


def test_every_queue_denies_non_tls(t):
    assert str(t.find_resources("AWS::SQS::QueuePolicy")).count("aws:SecureTransport") == 4


def test_worker_event_source_concurrency(t):
    t.has_resource_properties(
        "AWS::Lambda::EventSourceMapping",
        {
            "BatchSize": 1,
            "ScalingConfig": {"MaximumConcurrency": 25},
            "FunctionResponseTypes": ["ReportBatchItemFailures"],
        },
    )


def test_worker_handler_timeout_and_env(t):
    t.has_resource_properties(
        "AWS::Lambda::Function",
        {
            "Handler": "phish_backend.worker.run_scan.handler",
            "Timeout": WORKER_TIMEOUT_SECONDS,
            "Architectures": ["arm64"],
            "Runtime": "python3.13",
            "TracingConfig": {"Mode": "Active"},
            "Environment": {
                "Variables": Match.object_like(
                    {
                        "HARNESS_ARN": Match.any_value(),
                        "SCANS_TABLE": Match.any_value(),
                        "BATCHES_TABLE": Match.any_value(),
                        "STATS_TABLE": Match.any_value(),
                        "SCAN_QUEUE_URL": Match.any_value(),
                        "ARTIFACTS_BUCKET": Match.any_value(),
                        "GUARDRAIL_OUTPUT_ID": Match.any_value(),
                        "GUARDRAIL_OUTPUT_VERSION": Match.any_value(),
                        "RETENTION_DAYS": "90",
                        "LOG_LEVEL": "INFO",
                        "ORCHESTRATOR_MODEL_ID": "us.anthropic.claude-opus-5-5",
                        "SPECIALIST_MODEL_ID": "global.anthropic.claude-sonnet-5-5",
                    }
                )
            },
        },
    )


def test_splitter_env_and_trigger(t):
    env = function(t, "phish_backend.batch.split_csv.handler")["Properties"]["Environment"]
    assert {"GUARDRAIL_INPUT_ID", "GUARDRAIL_INPUT_VERSION", "RETENTION_DAYS"} <= set(
        env["Variables"]
    )
    (notification,) = t.find_resources("Custom::S3BucketNotifications").values()
    (config,) = notification["Properties"]["NotificationConfiguration"][
        "LambdaFunctionConfigurations"
    ]
    assert config["Events"] == ["s3:ObjectCreated:*"]
    rules = {(r["Name"], r["Value"]) for r in config["Filter"]["Key"]["FilterRules"]}
    assert rules == {("prefix", "uploads/"), ("suffix", ".csv")}


def test_aggregator_reads_scans_stream_with_its_own_dlq(t):
    t.has_resource_properties(
        "AWS::Lambda::EventSourceMapping",
        {
            "EventSourceArn": Match.any_value(),
            "StartingPosition": "LATEST",
            "BatchSize": 25,
            "FunctionResponseTypes": ["ReportBatchItemFailures"],
            "BisectBatchOnFunctionError": True,
            "MaximumRetryAttempts": 3,
            "DestinationConfig": {"OnFailure": {"Destination": Match.any_value()}},
        },
    )


def test_dead_letter_sweeper_drains_the_scan_dlq(t):
    function(t, "phish_backend.worker.dead_letter.handler")
    mappings = t.find_resources("AWS::Lambda::EventSourceMapping")
    assert len(mappings) == 3  # worker, aggregator, sweeper


def test_worker_can_invoke_harness_and_the_tools_runtime_but_no_other_runtime(t):
    text = role_policy_text(t, "phish_backend.worker.run_scan.handler")
    assert "bedrock-agentcore:InvokeHarness" in text
    # InvokeHarness is authorized as InvokeAgentRuntime on the harness ARN (AccessDenied in the
    # first API e2e, 2026-09-29), so that action is granted, but never on runtime/ ARNs.
    assert "bedrock-agentcore:InvokeAgentRuntime" in text
    assert ":runtime/" not in text
    # StopRuntimeSession was AccessDenied on the bare harness ARN; the endpoint ARN of the same
    # harness is granted too. The only other endpoint ARN is the tools Runtime's (precheck_url).
    assert "bedrock-agentcore:StopRuntimeSession" in text
    assert text.count("/runtime-endpoint/*") == 2
    assert "bedrock:ApplyGuardrail" in text


def test_aggregator_writes_stats_transactions(t):
    text = role_policy_text(t, "phish_backend.stats.aggregate.handler")
    for action in ("PutItem", "UpdateItem", "DeleteItem", "ConditionCheckItem"):
        assert f"dynamodb:{action}" in text, action


def test_alarms_notify_topic(t):
    alarms = t.find_resources("AWS::CloudWatch::Alarm")
    names = {a["Properties"]["AlarmName"] for a in alarms.values()}
    assert {
        "phish-scan-dlq-not-empty-dev",
        "phish-stats-stream-dlq-not-empty-dev",
        "phish-scan-queue-backlog-dev",
        "phish-worker-errors-dev",
        "phish-worker-throttles-dev",
    } <= names
    for a in alarms.values():
        assert a["Properties"]["AlarmActions"]


def test_queue_outputs_have_exact_keys(t):
    assert {"ScanQueueUrl", "ScanDlqUrl"} <= set(t.find_outputs("*"))


def role_statements(t, handler):
    role = function(t, handler)["Properties"]["Role"]["Fn::GetAtt"][0]
    return [
        s
        for p in t.find_resources("AWS::IAM::Policy").values()
        if {"Ref": role} in p["Properties"]["Roles"]
        for s in p["Properties"]["PolicyDocument"]["Statement"]
    ]


def test_worker_clears_stale_findings_under_scans_only(t):
    statements = role_statements(t, "phish_backend.worker.run_scan.handler")
    (listing,) = [s for s in statements if s["Action"] == "s3:ListBucket"]
    assert listing["Condition"] == {"StringLike": {"s3:prefix": "scans/*"}}
    (delete,) = [s for s in statements if s["Action"] == "s3:DeleteObject"]
    assert "/scans/*" in str(delete["Resource"])


REQUEUE = "phish_backend.worker.requeue_stuck.handler"


def test_requeue_stuck_runs_every_five_minutes_with_worker_env(t):
    worker_env = function(t, "phish_backend.worker.run_scan.handler")["Properties"]["Environment"]
    requeue = function(t, REQUEUE)["Properties"]
    assert set(requeue["Environment"]["Variables"]) == set(worker_env["Variables"])
    t.has_resource_properties(
        "AWS::Events::Rule",
        {
            "ScheduleExpression": "rate(5 minutes)",
            "State": "ENABLED",
            "Targets": [Match.object_like({"Arn": Match.any_value()})],
        },
    )


def test_requeue_stuck_permissions(t):
    statements = role_statements(t, REQUEUE)
    text = str(statements)
    for action in ("dynamodb:Query", "dynamodb:Scan", "dynamodb:UpdateItem", "sqs:SendMessage"):
        assert action in text, action
    ddb = [s for s in statements if "dynamodb:Query" in str(s["Action"])]
    resources = str([s["Resource"] for s in ddb])
    assert "DataScans" in resources and "DataBatches" in resources and "/index/*" in resources
    # The scans table is queried on its status index, never scanned: Scan is batches only.
    scans_scan = [
        s for s in statements if "dynamodb:Scan" in str(s["Action"]) and "DataScans" in str(s)
    ]
    assert scans_scan == []


def test_consumed_queues_outlast_their_consumer(t):
    # Lambda guidance: visibility timeout at least 6x the consumer timeout (cfn-lint E3505).
    sweeper = function(t, "phish_backend.worker.dead_letter.handler")["Properties"]["Timeout"]
    t.has_resource_properties(
        "AWS::SQS::Queue", {"QueueName": "phish-scan-dlq-dev", "VisibilityTimeout": 6 * sweeper}
    )


def test_splitter_async_failures_land_in_the_batch_dlq(t):
    t.has_resource_properties(
        "AWS::SQS::Queue",
        {
            "QueueName": "phish-batch-dlq-dev",
            "MessageRetentionPeriod": 1209600,
            "KmsMasterKeyId": Match.any_value(),
        },
    )
    (dlq_id,) = t.find_resources(
        "AWS::SQS::Queue", {"Properties": {"QueueName": "phish-batch-dlq-dev"}}
    )
    splitter = [
        k
        for k, v in t.find_resources("AWS::Lambda::Function").items()
        if v["Properties"]["Handler"] == "phish_backend.batch.split_csv.handler"
    ]
    t.has_resource_properties(
        "AWS::Lambda::EventInvokeConfig",
        {
            "FunctionName": {"Ref": splitter[0]},
            "MaximumRetryAttempts": 2,
            "DestinationConfig": {"OnFailure": {"Destination": {"Fn::GetAtt": [dlq_id, "Arn"]}}},
        },
    )
    t.has_resource_properties(
        "AWS::CloudWatch::Alarm",
        {
            "AlarmName": "phish-batch-dlq-not-empty-dev",
            "MetricName": "ApproximateNumberOfMessagesVisible",
            "Dimensions": [{"Name": "QueueName", "Value": {"Fn::GetAtt": [dlq_id, "QueueName"]}}],
            "Threshold": 0,
        },
    )
    assert "sqs:SendMessage" in role_policy_text(t, "phish_backend.batch.split_csv.handler")


def _statement_keys(t, handler, action):
    role = function(t, handler)["Properties"]["Role"]["Fn::GetAtt"][0]
    keys = set()
    for p in t.find_resources("AWS::IAM::Policy").values():
        if {"Ref": role} not in p["Properties"]["Roles"]:
            continue
        for st in p["Properties"]["PolicyDocument"]["Statement"]:
            actions = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
            if action in actions:
                resources = st["Resource"] if isinstance(st["Resource"], list) else [st["Resource"]]
                keys |= {r["Fn::Join"][1][-1].lstrip("/") for r in resources}
    return keys


def test_worker_deletes_only_findings(t):
    keys = _statement_keys(t, "phish_backend.worker.run_scan.handler", "s3:DeleteObject")
    assert keys == {"scans/*/findings/*"}


def test_worker_sends_low_effort_by_default(t):
    # The default: cdk.json ships orchestratorEffort=medium.
    env = function(t, "phish_backend.worker.run_scan.handler")["Properties"]["Environment"]
    assert env["Variables"]["ORCHESTRATOR_EFFORT"] == "medium"


def test_empty_effort_override_sends_none(app_context, test_env, tmp_path_factory):
    # -c orchestratorEffort= keeps the model default.
    app = cdk.App(context={**app_context, "orchestratorEffort": ""})
    stack = cdk.Stack(app, "S", env=test_env)
    cfg = load_config(app.node)
    assert cfg.orchestrator_effort == ""
    data = DataLayer(stack, "Data", cfg=cfg)
    agents = AgentsLayer(
        stack, "Agents", cfg=cfg, key=data.key, artifacts_bucket=data.artifacts_bucket
    )
    ScanPipeline(
        stack,
        "Pipeline",
        cfg=cfg,
        data=data,
        guardrails=Guardrails(stack, "G", cfg=cfg),
        agents=agents,
        backend_code=lambda_.Code.from_asset(str(tmp_path_factory.mktemp("code"))),
    )
    env = function(Template.from_stack(stack), "phish_backend.worker.run_scan.handler")
    assert "ORCHESTRATOR_EFFORT" not in env["Properties"]["Environment"]["Variables"]


def test_worker_turns_orchestrator_prompt_cache_on_by_default(t):
    env = function(t, "phish_backend.worker.run_scan.handler")["Properties"]["Environment"]
    assert env["Variables"]["ORCHESTRATOR_PROMPT_CACHE"] == "1"
    assert env["Variables"]["HARNESS_MAX_TOKENS"] == "8192"


def test_prompt_cache_flag_off(app_context):
    app = cdk.App(context={**app_context, "orchestratorPromptCache": "false"})
    assert load_config(app.node).orchestrator_prompt_cache is False


def test_worker_gets_the_tools_runtime_arn_and_may_invoke_only_it(t):
    env = function(t, "phish_backend.worker.run_scan.handler")["Properties"]["Environment"]
    assert "TOOLS_RUNTIME_ARN" in env["Variables"]
    arn = env["Variables"]["TOOLS_RUNTIME_ARN"]
    tools_logical_id = arn["Fn::GetAtt"][0]
    runtimes = t.find_resources("AWS::BedrockAgentCore::Runtime")
    assert runtimes[tools_logical_id]["Properties"]["AgentRuntimeName"] == "phish_tools_server"
    role = function(t, "phish_backend.worker.run_scan.handler")["Properties"]["Role"]["Fn::GetAtt"][
        0
    ]
    invoked = []
    for policy in t.find_resources("AWS::IAM::Policy").values():
        if {"Ref": role} not in policy["Properties"]["Roles"]:
            continue
        for st in policy["Properties"]["PolicyDocument"]["Statement"]:
            actions = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
            if "bedrock-agentcore:InvokeAgentRuntime" in actions:
                invoked.append(st)
    harness = [s for s in invoked if "Harness" in str(s["Resource"])]
    tools = [s for s in invoked if tools_logical_id in str(s["Resource"])]
    assert len(harness) == 1 and len(tools) == 1
    # Only the tools Runtime and its endpoints; no specialist.
    assert len(tools[0]["Resource"]) == 2
    assert "/runtime-endpoint/*" in str(tools[0]["Resource"])
    assert tools[0]["Action"] == "bedrock-agentcore:InvokeAgentRuntime"
    text = role_policy_text(t, "phish_backend.worker.run_scan.handler")
    for other in ("UrlAnalyst", "BrandVisual", "CodeAnalyst"):
        assert other not in text, other


def test_worker_keeps_the_harness_invoke_and_stop_grant(t):
    # Fixed 2026-10-05: StopRuntimeSession was denied without the endpoint ARN.
    role = function(t, "phish_backend.worker.run_scan.handler")["Properties"]["Role"]["Fn::GetAtt"][
        0
    ]
    for policy in t.find_resources("AWS::IAM::Policy").values():
        if {"Ref": role} not in policy["Properties"]["Roles"]:
            continue
        for st in policy["Properties"]["PolicyDocument"]["Statement"]:
            actions = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
            if "bedrock-agentcore:InvokeHarness" in actions:
                assert sorted(actions) == [
                    "bedrock-agentcore:InvokeAgentRuntime",
                    "bedrock-agentcore:InvokeHarness",
                    "bedrock-agentcore:StopRuntimeSession",
                ]
                assert len(st["Resource"]) == 2
                assert "/runtime-endpoint/*" in str(st["Resource"])
                return
    raise AssertionError("worker has no InvokeHarness statement")


def test_harness_turn_fits_inside_the_worker_timeout(t):
    # Both limits are per InvokeHarness call, and the worker makes up to two (verdict first,
    # then an optional second round). 240 s per call stays under the 300 s Lambda cap so one
    # call never outlives the worker; the worker passes a smaller timeoutSeconds for turn 2.
    harness = next(iter(t.find_resources("AWS::BedrockAgentCore::Harness").values()))
    assert harness["Properties"]["TimeoutSeconds"] < WORKER_TIMEOUT_SECONDS
    assert harness["Properties"]["MaxIterations"] == 8


def test_backend_environment_carries_an_opted_in_effort(app_context):
    from phish_infra.constructs.pipeline import backend_environment

    app = cdk.App(context={**app_context, "orchestratorEffort": "low"})
    cfg = load_config(app.node)

    class Named:
        table_name = bucket_name = harness_arn = "x"

    data = type(
        "D",
        (),
        {
            k: Named()
            for k in (
                "scans_table",
                "batches_table",
                "stats_table",
                "upload_bucket",
                "artifacts_bucket",
            )
        },
    )()
    env = backend_environment(cfg, data, Named())
    assert env["ORCHESTRATOR_EFFORT"] == "low"
    assert env["HARNESS_MAX_TOKENS"] == str(cfg.harness_max_tokens)
