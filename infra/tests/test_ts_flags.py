# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Capture, compact-view and latency flags: env vars and IAM.

codeModelView=compact, captureRecovery=true and every latency flag (directOrchestration,
localRdap, unanimousFastPath, directSpecialists, directTools, splitToolsRuntimes,
latencyBudgets, codeTextBudget=half) are the defaults. Each flag test starts from the Harness
layout (conftest.LATENCY_OFF) and turns one flag on, so it isolates that flag.
"""

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from phish_infra.config import load_config
from phish_infra.constructs.agents import AgentsLayer
from phish_infra.constructs.data import DataLayer


def synth(harness_context, test_env, **extra):
    app = cdk.App(context={**harness_context, **extra})
    stack = cdk.Stack(app, "S", env=test_env)
    cfg = load_config(app.node)
    data = DataLayer(stack, "Data", cfg=cfg)
    AgentsLayer(stack, "Agents", cfg=cfg, key=data.key, artifacts_bucket=data.artifacts_bucket)
    return Template.from_stack(stack)


def runtime_env(template, name):
    (runtime,) = [
        r
        for r in template.find_resources("AWS::BedrockAgentCore::Runtime").values()
        if r["Properties"]["AgentRuntimeName"] == f"phish_{name}"
    ]
    return runtime["Properties"]["EnvironmentVariables"]


def test_compact_view_by_default(harness_context):
    assert load_config(cdk.App(context=harness_context).node).code_model_view == "compact"


@pytest.mark.parametrize(
    ("raw", "view"),
    [("compact", "compact"), (" COMPACT ", "compact"), ("full", "full"), ("FULL", "full")],
)
def test_view_parses(harness_context, raw, view):
    cfg = load_config(cdk.App(context={**harness_context, "codeModelView": raw}).node)
    assert cfg.code_model_view == view


def test_unknown_view_fails_synth(harness_context):
    with pytest.raises(ValueError, match="codeModelView"):
        load_config(cdk.App(context={**harness_context, "codeModelView": "tiny"}).node)


def test_only_code_analyst_gets_the_compact_env(harness_context, test_env):
    on = synth(harness_context, test_env)
    off = synth(harness_context, test_env, codeModelView="full")
    assert runtime_env(on, "code_analyst")["CODE_MODEL_VIEW"] == "compact"
    assert "CODE_MODEL_VIEW" not in runtime_env(off, "code_analyst")
    for name in ("url_analyst", "brand_visual", "tools_server"):
        assert "CODE_MODEL_VIEW" not in runtime_env(on, name)


def test_capture_recovery_is_on_by_default_and_reaches_every_runtime(harness_context, test_env):
    assert load_config(cdk.App(context=harness_context).node).capture_recovery is True
    on = synth(harness_context, test_env)
    off = synth(harness_context, test_env, captureRecovery="false")
    for name in ("url_analyst", "brand_visual", "code_analyst", "tools_server", "dispatcher"):
        assert runtime_env(on, name)["CAPTURE_RECOVERY"] == "1"
        assert "CAPTURE_RECOVERY" not in runtime_env(off, name)


WORKER = "phish_backend.worker.run_scan.handler"


def pipeline(harness_context, test_env, tmp_path, **extra):
    from aws_cdk import aws_lambda as lambda_
    from aws_cdk.assertions import Template

    from phish_infra.constructs.agents import AgentsLayer
    from phish_infra.constructs.data import DataLayer
    from phish_infra.constructs.guardrails import Guardrails
    from phish_infra.constructs.pipeline import ScanPipeline

    app = cdk.App(context={**harness_context, **extra})
    stack = cdk.Stack(app, "S", env=test_env)
    cfg = load_config(app.node)
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
        backend_code=lambda_.Code.from_asset(str(tmp_path)),
    )
    return Template.from_stack(stack)


def worker(t):
    (fn,) = t.find_resources("AWS::Lambda::Function", {"Properties": {"Handler": WORKER}}).values()
    role = fn["Properties"]["Role"]["Fn::GetAtt"][0]
    statements = [
        st
        for p in t.find_resources("AWS::IAM::Policy").values()
        if {"Ref": role} in p["Properties"]["Roles"]
        for st in p["Properties"]["PolicyDocument"]["Statement"]
    ]
    return fn["Properties"]["Environment"]["Variables"], statements


def test_direct_orchestration_env_and_iam(harness_context, test_env, tmp_path):
    env_off, st_off = worker(pipeline(harness_context, test_env, tmp_path))
    env_on, st_on = worker(
        pipeline(harness_context, test_env, tmp_path, directOrchestration="true")
    )
    assert "ORCHESTRATION_MODE" not in env_off and "DISPATCHER_RUNTIME_ARN" not in env_off
    assert env_on["ORCHESTRATION_MODE"] == "direct" and env_on["DISPATCHER_RUNTIME_ARN"]
    off_text, on_text = str(st_off), str(st_on)
    assert "DispatcherRuntime" not in off_text and "bedrock:InvokeModel" not in off_text
    assert "DispatcherRuntime" in on_text and "bedrock:InvokeModel" in on_text
    # Still never a specialist Runtime, and no bare wildcard resource.
    for name in ("UrlAnalyst", "BrandVisual", "CodeAnalyst"):
        assert f"{name}Runtime" not in on_text
    # The flag adds no wildcard-resource statement (X-Ray and metrics already have one each).
    wild = lambda sts: sorted(str(st["Action"]) for st in sts if st.get("Resource") == "*")  # noqa: E731
    assert wild(st_on) == wild(st_off)


def test_direct_orchestration_rejects_the_registry(harness_context):
    with pytest.raises(ValueError, match="agentRegistry"):
        load_config(
            cdk.App(
                context={**harness_context, "directOrchestration": "true", "agentRegistry": "true"}
            ).node
        )


def test_local_rdap_only_on_url_analyst(harness_context, test_env):
    on = synth(harness_context, test_env, localRdap="true")
    assert runtime_env(on, "url_analyst")["LOCAL_RDAP"] == "1"
    assert "LOCAL_RDAP" not in runtime_env(synth(harness_context, test_env), "url_analyst")
    for name in ("brand_visual", "code_analyst", "tools_server"):
        assert "LOCAL_RDAP" not in runtime_env(on, name)


RUNTIMES = ("url_analyst", "brand_visual", "code_analyst", "tools_server", "dispatcher")


def cfg(harness_context, **extra):
    return load_config(cdk.App(context={**harness_context, **extra}).node)


def runtime_names(template):
    return sorted(
        r["Properties"]["AgentRuntimeName"]
        for r in template.find_resources("AWS::BedrockAgentCore::Runtime").values()
    )


def role_statements(template, runtime_name):
    (runtime,) = [
        r
        for r in template.find_resources("AWS::BedrockAgentCore::Runtime").values()
        if r["Properties"]["AgentRuntimeName"] == f"phish_{runtime_name}"
    ]
    role = runtime["Properties"]["RoleArn"]["Fn::GetAtt"][0]
    return [
        st
        for p in template.find_resources("AWS::IAM::Policy").values()
        if {"Ref": role} in p["Properties"]["Roles"]
        for st in p["Properties"]["PolicyDocument"]["Statement"]
    ]


def test_all_on_by_default(app_context):
    c = cfg(app_context)
    assert c.direct_orchestration and c.local_rdap and c.unanimous_fast_path
    assert c.direct_specialists and c.direct_tools and c.split_tools_runtimes
    assert c.latency_budgets and c.code_text_budget == "half"


def test_all_off_turns_every_flag_off(harness_context):
    c = cfg(harness_context)
    assert not (c.direct_orchestration or c.local_rdap or c.unanimous_fast_path)
    assert not (c.direct_specialists or c.direct_tools or c.split_tools_runtimes)
    assert not c.latency_budgets and c.code_text_budget == "full"


def test_parent_off_turns_its_dependents_off(app_context):
    c = cfg(app_context, directOrchestration="false")
    assert not (c.direct_orchestration or c.unanimous_fast_path or c.direct_specialists)
    assert c.direct_tools and c.split_tools_runtimes
    c = cfg(app_context, directTools="false")
    assert not (c.direct_tools or c.split_tools_runtimes) and c.direct_orchestration


def test_registry_falls_back_to_the_harness(app_context):
    c = cfg(app_context, agentRegistry="true")
    assert c.agent_registry and not c.direct_orchestration
    assert not (c.unanimous_fast_path or c.direct_specialists)
    assert c.direct_tools and c.latency_budgets


@pytest.mark.parametrize("flag", ["unanimousFastPath", "directSpecialists"])
def test_worker_flags_need_direct_orchestration(harness_context, flag):
    with pytest.raises(ValueError, match="directOrchestration"):
        cfg(harness_context, **{flag: "true"})
    assert cfg(harness_context, **{flag: "true", "directOrchestration": "true"})


def test_split_tools_runtimes_needs_direct_tools(harness_context):
    with pytest.raises(ValueError, match="directTools"):
        cfg(harness_context, splitToolsRuntimes="true")


def test_unknown_code_text_budget_fails_synth(harness_context):
    with pytest.raises(ValueError, match="codeTextBudget"):
        cfg(harness_context, codeTextBudget="quarter")


def test_unanimous_fast_path_env(harness_context, test_env, tmp_path):
    env_off, _ = worker(pipeline(harness_context, test_env, tmp_path, directOrchestration="true"))
    env_on, _ = worker(
        pipeline(
            harness_context,
            test_env,
            tmp_path,
            directOrchestration="true",
            unanimousFastPath="true",
        )
    )
    assert "UNANIMOUS_FAST_PATH" not in env_off and env_on["UNANIMOUS_FAST_PATH"] == "1"


def test_direct_specialists_env_and_iam(harness_context, test_env, tmp_path):
    base = {"directOrchestration": "true"}
    env_off, st_off = worker(pipeline(harness_context, test_env, tmp_path, **base))
    env_on, st_on = worker(
        pipeline(harness_context, test_env, tmp_path, **base, directSpecialists="true")
    )
    assert "DIRECT_SPECIALISTS" not in env_off
    assert env_on["DIRECT_SPECIALISTS"] == "1"
    for name in ("URL_ANALYST", "BRAND_VISUAL", "CODE_ANALYST"):
        assert env_on[f"{name}_RUNTIME_ARN"] and f"{name}_RUNTIME_ARN" not in env_off
    on_text = str(st_on)
    for name in ("UrlAnalyst", "BrandVisual", "CodeAnalyst"):
        assert f"{name}Runtime" in on_text and f"{name}Runtime" not in str(st_off)
    wild = lambda sts: sorted(str(st["Action"]) for st in sts if st.get("Resource") == "*")  # noqa: E731
    assert wild(st_on) == wild(st_off)


def test_direct_tools_env_and_iam(harness_context, test_env, tmp_path):
    on = synth(harness_context, test_env, directTools="true")
    off = synth(harness_context, test_env)
    for name in ("brand_visual", "code_analyst"):
        env = runtime_env(on, name)
        assert env["TOOLS_RUNTIME_ARN"] and env["TOOLS_SESSION_PER_SCAN"] == "1"
        assert "TOOLS_RUNTIME_ARN" not in runtime_env(off, name)
        assert "ToolsServerRuntime" in str(role_statements(on, name))
        assert "ToolsServerRuntime" not in str(role_statements(off, name))
    url = runtime_env(on, "url_analyst")
    assert url["LOCAL_RDAP"] == "1" and "TOOLS_RUNTIME_ARN" not in url
    assert "ToolsServerRuntime" not in str(role_statements(on, "url_analyst"))
    # The tools Gateway stays: the Harness path and a rollback still use it.
    assert runtime_env(on, "brand_visual")["TOOLS_GATEWAY_URL"]
    env_on, _ = worker(pipeline(harness_context, test_env, tmp_path, directTools="true"))
    env_off, _ = worker(pipeline(harness_context, test_env, tmp_path))
    assert env_on["TOOLS_SESSION_PER_SCAN"] == "1" and "TOOLS_SESSION_PER_SCAN" not in env_off


def test_split_tools_runtimes_gives_each_capture_its_own_copy(harness_context, test_env):
    one = synth(harness_context, test_env, directTools="true")
    split = synth(harness_context, test_env, directTools="true", splitToolsRuntimes="true")
    added = sorted(set(runtime_names(split)) - set(runtime_names(one)))
    assert added == ["phish_tools_brand", "phish_tools_code"]
    for agent, copy in (("brand_visual", "ToolsBrand"), ("code_analyst", "ToolsCode")):
        statements = str(role_statements(split, agent))
        assert f"{copy}Runtime" in statements and "ToolsServerRuntime" not in statements
        assert f"{copy}Runtime" in str(runtime_env(split, agent)["TOOLS_RUNTIME_ARN"])
    for copy in ("tools_brand", "tools_code"):
        assert (
            runtime_env(split, copy)["BROWSER_ID"]
            == runtime_env(split, "tools_server")["BROWSER_ID"]
        )


@pytest.mark.parametrize(
    ("extra", "key", "value"),
    [
        ({"latencyBudgets": "true"}, "LATENCY_BUDGETS", "1"),
        ({"codeTextBudget": "half"}, "CODE_TEXT_BUDGET", "half"),
    ],
)
def test_agent_budget_flags_reach_every_runtime(harness_context, test_env, extra, key, value):
    on = synth(harness_context, test_env, **extra)
    off = synth(harness_context, test_env)
    for name in RUNTIMES:
        assert runtime_env(on, name)[key] == value
        assert key not in runtime_env(off, name)


def _custom_resource_policy_chars(template) -> int:
    """Inline policy characters on the AwsCustomResource singleton role (IAM caps a role's
    inline policies at 10,240 characters in total)."""
    import json

    return sum(
        len(json.dumps(p["Properties"]["PolicyDocument"], separators=(",", ":")))
        for p in template.find_resources("AWS::IAM::Policy").values()
        if any("AWS679f53fac" in json.dumps(r) for r in p["Properties"].get("Roles", []))
    )


def test_split_runtimes_do_not_grow_the_custom_resource_role(harness_context, test_env):
    default = _custom_resource_policy_chars(synth(harness_context, test_env))
    split = _custom_resource_policy_chars(
        synth(harness_context, test_env, directTools="true", splitToolsRuntimes="true")
    )
    # Two more Runtimes, yet less policy: the log-group statement is carried once per Runtime.
    assert split <= default
