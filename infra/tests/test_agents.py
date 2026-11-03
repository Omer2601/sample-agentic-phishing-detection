# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json
from pathlib import Path

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Match, Template

from phish_infra.config import load_config
from phish_infra.constructs import agents as agents_module
from phish_infra.constructs.agents import AgentsLayer
from phish_infra.constructs.data import DataLayer

RUNTIME_OUTPUTS = (
    "UrlAnalystRuntimeArn",
    "BrandVisualRuntimeArn",
    "CodeAnalystRuntimeArn",
    "DispatcherRuntimeArn",
)
SPECIALIST_TARGETS = ["brand-visual", "code-analyst", "url-analyst"]


def synth(app_context, test_env, **extra):
    app = cdk.App(context={**app_context, **extra})
    stack = cdk.Stack(app, "S", env=test_env)
    cfg = load_config(app.node)
    data = DataLayer(stack, "Data", cfg=cfg)
    AgentsLayer(stack, "Agents", cfg=cfg, key=data.key, artifacts_bucket=data.artifacts_bucket)
    return Template.from_stack(stack)


@pytest.fixture(scope="module")
def t(harness_context, test_env):
    """The Harness layout (latency flags off): dispatcher, tools server, no Agent Registry."""
    return synth(harness_context, test_env)


@pytest.fixture(scope="module")
def reg(harness_context, test_env):
    """-c agentRegistry=true on the Harness layout."""
    return synth(harness_context, test_env, agentRegistry=True)


def policies_with(t, needle):
    return [p for p in t.find_resources("AWS::IAM::Policy").values() if needle in str(p)]


def test_five_mcp_runtimes(t):
    runtimes = t.find_resources("AWS::BedrockAgentCore::Runtime")
    names = sorted(r["Properties"]["AgentRuntimeName"] for r in runtimes.values())
    assert names == [
        "phish_brand_visual",
        "phish_code_analyst",
        "phish_dispatcher",
        "phish_tools_server",
        "phish_url_analyst",
    ]
    for r in runtimes.values():
        p = r["Properties"]
        assert p["ProtocolConfiguration"] == "MCP"
        assert p["NetworkConfiguration"] == {"NetworkMode": "PUBLIC"}
        assert p["LifecycleConfiguration"] == {"IdleRuntimeSessionTimeout": 60, "MaxLifetime": 1800}
    for name in ("url_analyst", "brand_visual", "code_analyst"):
        env = runtime_of(t, name)["Properties"]["EnvironmentVariables"]
        assert env["MODEL_ID"] == "global.anthropic.claude-sonnet-5-5"
        assert set(env) >= {"ARTIFACTS_BUCKET", "MODEL_ID", "TOOLS_GATEWAY_URL", "LOG_LEVEL"}


@pytest.mark.parametrize("registry", [False, True])
def test_images_are_arm64_builds_of_one_dockerfile(app_context, test_env, registry):
    app = cdk.App(context={**app_context, "agentRegistry": registry})
    stack = cdk.Stack(app, "S", env=test_env)
    cfg = load_config(app.node)
    data = DataLayer(stack, "Data", cfg=cfg)
    AgentsLayer(stack, "Agents", cfg=cfg, key=data.key, artifacts_bucket=data.artifacts_bucket)
    assembly = app.synth()
    manifest = Path(assembly.directory) / f"{stack.artifact_id}.assets.json"
    docker = json.loads(manifest.read_text())["dockerImages"]
    sources = [d["source"] for d in docker.values()]
    assert sorted(s["dockerBuildArgs"]["AGENT"] for s in sources) == [
        "brand_visual",
        "code_analyst",
        "dispatcher",
        "tools_server",
        "url_analyst",
    ]
    for s in sources:
        assert s["dockerFile"] == "agents/Dockerfile"
        assert s["platform"] == "linux/arm64"


def test_specialists_reach_only_sonnet(t):
    for policy in policies_with(t, "inference-profile"):
        text = str(policy)
        if "claude-sonnet-5-5" in text:
            assert "claude-opus" not in text


def test_specialists_write_only_scan_artifacts(t):
    for policy in policies_with(t, "s3:PutObject"):
        text = str(policy)
        assert "/scans/*" in text


def test_gateway_is_iam_mcp(t):
    t.has_resource_properties(
        "AWS::BedrockAgentCore::Gateway",
        {"Name": "phish-specialists", "ProtocolType": "MCP", "AuthorizerType": "AWS_IAM"},
    )
    t.resource_count_is("AWS::Cognito::UserPool", 0)


def test_gateway_mcp_configuration_is_not_empty(t):
    # The service rejects an empty Mcp block with "MCP configuration cannot be empty"
    # (first deploy, 2026-09-29), and synth alone does not catch it.
    gateway = next(iter(t.find_resources("AWS::BedrockAgentCore::Gateway").values()))
    mcp = gateway["Properties"]["ProtocolConfiguration"]["Mcp"]
    assert mcp.get("SupportedVersions"), mcp


def test_specialists_gateway_has_the_dispatcher_and_the_three_specialists(t):
    on_specialists = sorted(
        x["Name"]
        for x in targets_of(t).values()
        if gateway_id(t, "phish-specialists") in json.dumps(x["GatewayIdentifier"])
    )
    assert on_specialists == sorted(["dispatcher", *SPECIALIST_TARGETS])
    for name in on_specialists:
        p = targets_of(t)[name]
        assert "McpServer" in p["TargetConfiguration"]["Mcp"]
        (provider,) = p["CredentialProviderConfigurations"]
        assert provider["CredentialProviderType"] == "GATEWAY_IAM_ROLE"
        assert provider["CredentialProvider"]["IamCredentialProvider"]["Service"] == (
            "bedrock-agentcore"
        )


def test_harness_uses_opus_and_only_gateway_tools(t):
    t.has_resource_properties(
        "AWS::BedrockAgentCore::Harness",
        {
            "HarnessName": "phish_orchestrator",
            "Model": {"BedrockModelConfig": {"ModelId": "us.anthropic.claude-opus-5-5"}},
            "Tools": [
                {
                    "Type": "agentcore_gateway",
                    "Name": "specialists",
                    "Config": {
                        "AgentCoreGateway": {
                            "GatewayArn": Match.any_value(),
                            "OutboundAuth": {"AwsIam": {}},
                        }
                    },
                }
            ],
            "AllowedTools": ["@specialists/*"],
            "MaxTokens": 8192,
            "MaxIterations": 8,
            "TimeoutSeconds": 240,
            "SystemPrompt": [{"Text": Match.string_like_regexp("orchestrator prompt")}],
        },
    )


def test_harness_is_tagged_and_carries_no_guardrail_config(app_context, test_env):
    app = cdk.App(context=app_context)
    stack = cdk.Stack(app, "S", env=test_env)
    cfg = load_config(app.node)
    from phish_infra.common import apply_tags

    apply_tags(stack, cfg)
    data = DataLayer(stack, "Data", cfg=cfg)
    AgentsLayer(stack, "Agents", cfg=cfg, key=data.key, artifacts_bucket=data.artifacts_bucket)
    h = next(
        iter(Template.from_stack(stack).find_resources("AWS::BedrockAgentCore::Harness").values())
    )
    assert "GuardrailConfiguration" not in h["Properties"]
    assert {"Key": "Project", "Value": "phish-triage"} in h["Properties"]["Tags"]


def test_harness_role_has_the_spike_proven_grants(t):
    text = str(policies_with(t, "bedrock-agentcore:InvokeGateway"))
    for action in ("GetHarness", "logs:PutLogEvents"):
        assert action in text, action
    assert "/aws/bedrock-agentcore/phish_orchestrator" in text


@pytest.mark.parametrize("registry", [False, True])
def test_harness_memory_is_disabled_and_the_role_has_no_memory_grant(
    app_context, test_env, registry
):
    # Managed memory stored facts under one shared actor for every user's scans.
    template = synth(app_context, test_env, agentRegistry=registry)
    h = next(iter(template.find_resources("AWS::BedrockAgentCore::Harness").values()))
    assert h["Properties"]["Memory"] == {"Disabled": {}}
    text = str(policies_with(template, "bedrock-agentcore:InvokeGateway"))
    for action in ("ListEvents", "CreateEvent", "RetrieveMemoryRecords", ":memory/"):
        assert action not in text, action


def test_harness_waits_for_targets(t):
    h = next(iter(t.find_resources("AWS::BedrockAgentCore::Harness").values()))
    targets = {
        lid
        for lid, x in t.find_resources("AWS::BedrockAgentCore::GatewayTarget").items()
        if gateway_id(t, "phish-specialists") in json.dumps(x["Properties"]["GatewayIdentifier"])
    }
    assert len(targets) == 4 and targets <= set(h["DependsOn"])


def test_stack_outputs_have_exact_keys(t):
    outputs = t.find_outputs("*")
    for key in (
        "OrchestratorHarnessArn",
        "GatewayArn",
        "ToolsGatewayArn",
        "ToolsServerRuntimeArn",
        *RUNTIME_OUTPUTS,
    ):
        assert key in outputs, key


def test_missing_prompt_is_a_clear_error(app_context, test_env, monkeypatch, tmp_path):
    monkeypatch.setattr(agents_module, "ORCHESTRATOR_PROMPT", tmp_path / "missing.md")
    with pytest.raises(FileNotFoundError, match="Orchestrator prompt"):
        synth(app_context, test_env)


def test_image_context_keeps_the_lockfile():
    # agents/Dockerfile runs `uv export --frozen`, which needs uv.lock in the build context.
    assert "!uv.lock" in agents_module.IMAGE_EXCLUDES
    assert "uv.lock" not in agents_module.IMAGE_EXCLUDES


def test_browser_actions_are_exactly_the_interface_list(t):
    (policy,) = policies_with(t, "bedrock-agentcore:StartBrowserSession")
    (stmt,) = [
        s
        for s in policy["Properties"]["PolicyDocument"]["Statement"]
        if "bedrock-agentcore:StartBrowserSession" in s["Action"]
    ]
    assert sorted(stmt["Action"]) == [
        "bedrock-agentcore:ConnectBrowserAutomationStream",
        "bedrock-agentcore:GetBrowserSession",
        "bedrock-agentcore:StartBrowserSession",
        "bedrock-agentcore:StopBrowserSession",
    ]


def _runtime_put_resources(t, name):
    """Object keys a specialist runtime role may PutObject, as `scans/...` suffixes."""
    runtime = next(
        r
        for r in t.find_resources("AWS::BedrockAgentCore::Runtime").values()
        if r["Properties"]["AgentRuntimeName"] == f"phish_{name}"
    )
    role = runtime["Properties"]["RoleArn"]["Fn::GetAtt"][0]
    keys = set()
    for policy in t.find_resources("AWS::IAM::Policy").values():
        if {"Ref": role} not in policy["Properties"]["Roles"]:
            continue
        for st in policy["Properties"]["PolicyDocument"]["Statement"]:
            actions = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
            if "s3:PutObject" not in actions:
                continue
            resources = st["Resource"] if isinstance(st["Resource"], list) else [st["Resource"]]
            for res in resources:
                keys.add(res["Fn::Join"][1][-1].lstrip("/"))
    return keys


FINDINGS = {f"scans/*/findings/{n}.json" for n in ("url_analyst", "brand_visual", "code_analyst")}


@pytest.mark.parametrize(
    "name,keys",
    [
        ("url_analyst", {"scans/*/findings/url_analyst.json"}),
        ("brand_visual", {"scans/*/findings/brand_visual.json"}),
        ("code_analyst", {"scans/*/findings/code_analyst.json"}),
        ("tools_server", {"scans/*/screenshot.png", "scans/*/capture.json"}),
        # Only for the error Finding of a specialist that could not run.
        ("dispatcher", FINDINGS),
    ],
)
def test_each_runtime_writes_only_its_own_keys(t, name, keys):
    assert _runtime_put_resources(t, name) == keys


def test_runtime_log_groups_are_adopted_not_precreated(t):
    # The service creates /aws/bedrock-agentcore/runtimes/{agentRuntimeId}-DEFAULT as soon as
    # the Runtime starts, so an AWS::Logs::LogGroup with that name fails with AlreadyExists
    # (second deploy, 2026-09-29). The stack adopts the group instead: create if missing,
    # then set the retention and the CMK, and delete it with the stack in dev.
    runtimes = t.find_resources("AWS::BedrockAgentCore::Runtime")
    assert len(runtimes) == 5
    for group in t.find_resources("AWS::Logs::LogGroup").values():
        assert "bedrock-agentcore/runtimes" not in json.dumps(group)
    calls = [
        json.dumps(r["Properties"])
        for r in t.find_resources("Custom::AWS").values()
        if "bedrock-agentcore/runtimes" in json.dumps(r["Properties"])
    ]
    for logical_id in runtimes:
        mine = [c for c in calls if f'"{logical_id}", "AgentRuntimeId"' in c]
        joined = " ".join(mine)
        for action in ("createLogGroup", "putRetentionPolicy", "associateKmsKey"):
            assert f'\\"action\\":\\"{action}\\"' in joined, (logical_id, action)
        assert "ResourceAlreadyExistsException" in joined
        # jsii enums serialize by name, so an enum here would send "ONE_MONTH" (third deploy).
        assert '\\"retentionInDays\\":30' in joined, joined
        assert "deleteLogGroup" in joined


def test_log_group_adoption_is_scoped_to_runtime_groups(t):
    for policy in t.find_resources("AWS::IAM::Policy").values():
        for statement in policy["Properties"]["PolicyDocument"]["Statement"]:
            actions = statement["Action"]
            actions = actions if isinstance(actions, list) else [actions]
            if any(a in actions for a in ("logs:AssociateKmsKey", "logs:PutRetentionPolicy")):
                text = json.dumps(statement["Resource"])
                assert "bedrock-agentcore/runtimes/" in text, statement
                assert statement["Resource"] != "*"


@pytest.mark.parametrize(
    "description,resource",
    [
        ("phish Gateway: SigV4 caller of the specialist tools", "gateway/phish-specialists*"),
        ("phish orchestrator Harness execution role", "harness/phish_orchestrator*"),
    ],
)
def test_trust_policy_source_arn_names_the_one_resource(t, description, resource):
    (role,) = t.find_resources(
        "AWS::IAM::Role", {"Properties": {"Description": description}}
    ).values()
    (statement,) = role["Properties"]["AssumeRolePolicyDocument"]["Statement"]
    source_arns = statement["Condition"]["ArnLike"]["aws:SourceArn"]
    source_arns = source_arns if isinstance(source_arns, list) else [source_arns]
    lasts = [a["Fn::Join"][1][-1] if isinstance(a, dict) else a for a in source_arns]
    assert any(last.endswith(f":{resource}") for last in lasts), source_arns
    assert "aws:SourceAccount" in statement["Condition"]["StringEquals"]


def test_harness_role_trusts_the_harness_backing_runtime(t):
    # Fifth deploy (2026-09-29): the harness creates a runtime named harness_<harness name>,
    # and that CreateAgentRuntime validates the role against the runtime ARN, not the harness.
    (role,) = t.find_resources(
        "AWS::IAM::Role",
        {"Properties": {"Description": "phish orchestrator Harness execution role"}},
    ).values()
    (statement,) = role["Properties"]["AssumeRolePolicyDocument"]["Statement"]
    arns = json.dumps(statement["Condition"]["ArnLike"]["aws:SourceArn"])
    assert ":harness/phish_orchestrator*" in arns
    assert ":runtime/harness_phish_orchestrator*" in arns


def test_log_group_adoption_can_describe_the_cmk(t):
    # Fourth deploy (2026-09-29): AssociateKmsKey failed because the custom resource role had
    # no kms:DescribeKey on the data key.
    found = False
    for policy in t.find_resources("AWS::IAM::Policy").values():
        statements = policy["Properties"]["PolicyDocument"]["Statement"]
        if not any("logs:AssociateKmsKey" in json.dumps(s["Action"]) for s in statements):
            continue
        describe = [s for s in statements if s["Action"] == "kms:DescribeKey"]
        assert describe, statements
        assert all("DataDataKey" in json.dumps(s["Resource"]) for s in describe)
        found = True
    assert found


# ── shared helpers ───────────────────────────────────────────────────────────────────────


def targets_of(template):
    return {
        x["Properties"]["Name"]: x["Properties"]
        for x in template.find_resources("AWS::BedrockAgentCore::GatewayTarget").values()
    }


def gateway_id(template, name):
    return next(
        lid
        for lid, g in template.find_resources("AWS::BedrockAgentCore::Gateway").items()
        if g["Properties"]["Name"] == name
    )


def role_id(template, description):
    return next(
        lid
        for lid, r in template.find_resources("AWS::IAM::Role").items()
        if r["Properties"].get("Description") == description
    )


def statements_of_role(template, role):
    return [
        s
        for p in template.find_resources("AWS::IAM::Policy").values()
        if {"Ref": role} in p["Properties"]["Roles"]
        for s in p["Properties"]["PolicyDocument"]["Statement"]
    ]


def harness_prompt(template):
    harness = next(iter(template.find_resources("AWS::BedrockAgentCore::Harness").values()))
    (block,) = harness["Properties"]["SystemPrompt"]
    return block["Text"]


def gateway_props(template, name):
    (gw,) = [
        g["Properties"]
        for g in template.find_resources("AWS::BedrockAgentCore::Gateway").values()
        if g["Properties"]["Name"] == name
    ]
    return gw


def runtime_of(template, name):
    return next(
        r
        for r in template.find_resources("AWS::BedrockAgentCore::Runtime").values()
        if r["Properties"]["AgentRuntimeName"] == f"phish_{name}"
    )


def role_statements(template, runtime):
    role = runtime["Properties"]["RoleArn"]["Fn::GetAtt"][0]
    return [
        st
        for p in template.find_resources("AWS::IAM::Policy").values()
        if {"Ref": role} in p["Properties"]["Roles"]
        for st in p["Properties"]["PolicyDocument"]["Statement"]
    ]


def actions_of(statement):
    a = statement["Action"]
    return a if isinstance(a, list) else [a]


# ── -c agentRegistry: off by default ────────────────────────────────────────────────────


def test_registry_is_off_by_default(app_context, t):
    assert app_context["agentRegistry"] is False
    for kind in ("AWS::AgentRegistry::Registry", "AWS::AgentRegistry::RegistryRecord"):
        t.resource_count_is(kind, 0)
    assert "registry" not in targets_of(t)
    text = json.dumps(t.to_json())
    assert "agent-registry" not in text and "SubmitRegistryRecordForApproval" not in text
    assert "RegistryArn" not in t.find_outputs("*")
    assert "Step 0" not in harness_prompt(t)


def test_registry_flag_adds_the_catalog_its_target_and_the_lookup_step(reg):
    assert sorted(targets_of(reg)) == sorted(
        ["dispatcher", "registry", "tools", *SPECIALIST_TARGETS]
    )
    gateways = sorted(
        g["Properties"]["Name"]
        for g in reg.find_resources("AWS::BedrockAgentCore::Gateway").values()
    )
    assert gateways == ["phish-specialists", "phish-tools"]
    prompt = harness_prompt(reg)
    assert prompt.index("## Step 0") < prompt.index("## Step 1")
    assert prompt.count("## Step 0") == 1


def test_the_flag_changes_nothing_but_the_registry(t, reg):
    def kinds(template):
        return {
            v["Type"]
            for v in template.to_json()["Resources"].values()
            if "AgentRegistry" not in v["Type"]
        }

    assert kinds(t) == kinds(reg)
    assert len(t.find_resources("AWS::BedrockAgentCore::Runtime")) == len(
        reg.find_resources("AWS::BedrockAgentCore::Runtime")
    )


def test_composed_prompt_inserts_the_real_registry_step_before_round_one(monkeypatch):
    from phish_infra.common import REPO_ROOT

    orchestrator = REPO_ROOT / "agents" / "orchestrator"
    monkeypatch.setattr(agents_module, "ORCHESTRATOR_PROMPT", orchestrator / "prompt.md")
    monkeypatch.setattr(
        agents_module, "ORCHESTRATOR_REGISTRY_STEP", orchestrator / "registry_step.md"
    )
    base = agents_module.orchestrator_prompt(False)
    assert base == (orchestrator / "prompt.md").read_text()
    assert "registry" not in base.lower()
    composed = agents_module.orchestrator_prompt(True)
    assert (
        composed.index("## Step 0")
        < composed.index("## Step 1")
        < composed.index("## Optional second round")
    )
    assert "registry___search_discoverable_registry_records" in composed
    assert (
        composed.replace((orchestrator / "registry_step.md").read_text().strip() + "\n\n", "")
        == base
    )


def test_a_prompt_without_the_round_one_heading_is_a_clear_error(monkeypatch, tmp_path):
    prompt = tmp_path / "prompt.md"
    prompt.write_text("no headings here")
    monkeypatch.setattr(agents_module, "ORCHESTRATOR_PROMPT", prompt)
    with pytest.raises(ValueError, match="## Step 1"):
        agents_module.orchestrator_prompt(True)


# ── tools server and its Gateway (always deployed) ──────────────────────────────────────


def test_tools_gateway_has_one_target_on_the_tools_runtime(t):
    reg = t
    on_tools = [
        x["Properties"]
        for x in reg.find_resources("AWS::BedrockAgentCore::GatewayTarget").values()
        if gateway_id(reg, "phish-tools") in json.dumps(x["Properties"]["GatewayIdentifier"])
    ]
    assert [t["Name"] for t in on_tools] == ["tools"]
    (provider,) = on_tools[0]["CredentialProviderConfigurations"]
    assert provider["CredentialProvider"]["IamCredentialProvider"]["Service"] == "bedrock-agentcore"
    assert gateway_props(reg, "phish-tools")["AuthorizerType"] == "AWS_IAM"
    mcp = gateway_props(reg, "phish-tools")["ProtocolConfiguration"]["Mcp"]
    assert sorted(mcp["SupportedVersions"]) == ["2025-03-26", "2025-06-18"]


def test_harness_cannot_reach_the_tools_gateway(t):
    reg = t
    harness_role = next(
        lid
        for lid, r in reg.find_resources("AWS::IAM::Role").items()
        if r["Properties"].get("Description") == "phish orchestrator Harness execution role"
    )
    tools_gw = next(
        lid
        for lid, g in reg.find_resources("AWS::BedrockAgentCore::Gateway").items()
        if g["Properties"]["Name"] == "phish-tools"
    )
    for policy in reg.find_resources("AWS::IAM::Policy").values():
        if {"Ref": harness_role} in policy["Properties"]["Roles"]:
            assert tools_gw not in json.dumps(policy)


def test_only_the_tools_runtime_can_use_the_browser(t):
    reg = t
    for name in ("url_analyst", "brand_visual", "code_analyst"):
        text = json.dumps(role_statements(reg, runtime_of(reg, name)))
        assert "BrowserSession" not in text, name
    tools = role_statements(reg, runtime_of(reg, "tools_server"))
    assert any("bedrock-agentcore:StartBrowserSession" in actions_of(s) for s in tools)
    assert not any(a.startswith("bedrock:") for s in tools for a in actions_of(s))


def test_tools_runtime_writes_screenshot_and_capture_only(t):
    reg = t
    keys = set()
    for st in role_statements(reg, runtime_of(reg, "tools_server")):
        if "s3:PutObject" in actions_of(st):
            res = st["Resource"] if isinstance(st["Resource"], list) else [st["Resource"]]
            keys |= {r["Fn::Join"][1][-1].lstrip("/") for r in res}
    assert keys == {"scans/*/screenshot.png", "scans/*/capture.json"}


@pytest.mark.parametrize("name", ["url_analyst", "brand_visual", "code_analyst"])
def test_specialists_write_only_their_finding_and_call_the_tools_gateway(t, name):
    reg = t
    runtime = runtime_of(reg, name)
    keys = set()
    for st in role_statements(reg, runtime):
        if "s3:PutObject" in actions_of(st):
            res = st["Resource"] if isinstance(st["Resource"], list) else [st["Resource"]]
            keys |= {r["Fn::Join"][1][-1].lstrip("/") for r in res}
    assert keys == {f"scans/*/findings/{name}.json"}
    env = runtime["Properties"]["EnvironmentVariables"]
    assert "TOOLS_GATEWAY_URL" in env and env["TOOLS_GATEWAY_REGION"] == "us-west-2"
    assert "BROWSER_ID" not in env
    invokes = [
        s
        for s in role_statements(reg, runtime)
        if "bedrock-agentcore:InvokeGateway" in actions_of(s)
    ]
    assert len(invokes) == 1


def test_only_brand_visual_reads_the_screenshot_back(t):
    reg = t
    for name in ("url_analyst", "brand_visual", "code_analyst"):
        statements = role_statements(reg, runtime_of(reg, name))
        reads = [s for s in statements if "s3:GetObject" in actions_of(s)]
        assert bool(reads) == (name == "brand_visual"), name
        if reads:
            assert "scans/*/screenshot.png" in json.dumps(reads)


def test_registry_catalogs_the_five_mcp_servers(reg):
    reg.resource_count_is("AWS::AgentRegistry::Registry", 1)
    reg.has_resource_properties(
        "AWS::AgentRegistry::Registry",
        {
            "AuthorizerType": "AWS_IAM",
            "ApprovalConfiguration": {"AutoApprovalRules": ["APPROVE_ALL"]},
        },
    )
    records = reg.find_resources("AWS::AgentRegistry::RegistryRecord")
    assert sorted(r["Properties"]["Name"] for r in records.values()) == [
        "BrandVisual",
        "CodeAnalyst",
        "Dispatcher",
        "PhishTools",
        "UrlAnalyst",
    ]
    for r in records.values():
        assert r["Properties"]["RecordType"] == "MCP"
        assert "McpServer" in r["Properties"]["Descriptors"]
    text = json.dumps(records)
    for tool in ("capture_page", "capture_page_code", "whois_lookup", "analyze", "analyze_all"):
        assert tool in text


def test_registry_outputs(reg):
    outputs = reg.find_outputs("*")
    for key in ("RegistryArn", "RegistryMcpUrl", "ToolsGatewayArn", "ToolsGatewayUrl"):
        assert key in outputs, key


def test_the_prompt_documents_the_gateway_target_names():
    from phish_infra.common import REPO_ROOT

    text = (REPO_ROOT / "agents" / "orchestrator" / "prompt.md").read_text()
    for target in (agents_module.DISPATCHER_TARGET_NAME, *agents_module.TARGET_NAMES.values()):
        assert f"`{target}___" in text, target


def test_registry_outside_registry_regions_skips_the_catalog_and_the_step(app_context):
    app = cdk.App(context={**app_context, "agentRegistry": True})
    stack = cdk.Stack(app, "S", env=cdk.Environment(account="123456789012", region="eu-central-1"))
    cfg = load_config(app.node)
    data = DataLayer(stack, "Data", cfg=cfg)
    AgentsLayer(stack, "Agents", cfg=cfg, key=data.key, artifacts_bucket=data.artifacts_bucket)
    template = Template.from_stack(stack)
    template.resource_count_is("AWS::AgentRegistry::Registry", 0)
    assert "tools" in targets_of(template) and "dispatcher" in targets_of(template)
    assert "Step 0" not in harness_prompt(template)


def test_web_search_stays_at_the_edge_in_a_region_without_the_connector(t):
    reg = t
    assert all(
        "WebSearch" not in json.dumps(t)
        for t in reg.find_resources("AWS::BedrockAgentCore::GatewayTarget").values()
    )


def test_web_search_folds_into_the_tools_gateway_where_the_connector_exists(app_context):
    app = cdk.App(context=app_context)
    stack = cdk.Stack(app, "S", env=cdk.Environment(account="123456789012", region="us-east-1"))
    cfg = load_config(app.node)
    data = DataLayer(stack, "Data", cfg=cfg)
    AgentsLayer(stack, "Agents", cfg=cfg, key=data.key, artifacts_bucket=data.artifacts_bucket)
    template = Template.from_stack(stack)
    assert sorted(targets_of(template)) == [
        "brand-visual",
        "code-analyst",
        "dispatcher",
        "tools",
        "url-analyst",
        "web-search",
    ]
    env = runtime_of(template, "brand_visual")["Properties"]["EnvironmentVariables"]
    assert "WEB_SEARCH_GATEWAY_URL" in env
    assert (
        "WEB_SEARCH_GATEWAY_URL"
        not in runtime_of(template, "code_analyst")["Properties"]["EnvironmentVariables"]
    )


# ── dispatcher ───────────────────────────────────────────────────────────────────────────

GATEWAY_ROLE = "phish Gateway: SigV4 caller of the specialist tools"


def invoke_resources(template, role):
    (invoke,) = [
        s
        for s in statements_of_role(template, role)
        if "bedrock-agentcore:InvokeAgentRuntime" in actions_of(s)
    ]
    return json.dumps(invoke["Resource"]), len(invoke["Resource"])


def runtime_logical_id(template, name):
    return next(
        lid
        for lid, r in template.find_resources("AWS::BedrockAgentCore::Runtime").items()
        if r["Properties"]["AgentRuntimeName"] == f"phish_{name}"
    )


def test_specialists_gateway_role_invokes_the_dispatcher_and_the_specialists_only(t):
    text, count = invoke_resources(t, role_id(t, GATEWAY_ROLE))
    assert count == 8  # dispatcher and three specialists, and their endpoints
    for name in ("dispatcher", "url_analyst", "brand_visual", "code_analyst"):
        assert runtime_logical_id(t, name) in text, name
    assert runtime_logical_id(t, "tools_server") not in text


def test_dispatcher_role_invokes_only_the_three_specialists(t):
    runtime = runtime_of(t, "dispatcher")
    role = runtime["Properties"]["RoleArn"]["Fn::GetAtt"][0]
    text, count = invoke_resources(t, role)
    assert count == 6  # three specialist Runtimes and their endpoints
    for name in ("url_analyst", "brand_visual", "code_analyst"):
        assert runtime_logical_id(t, name) in text, name
    for name in ("dispatcher", "tools_server"):
        assert runtime_logical_id(t, name) not in text, name
    actions = {a for s in statements_of_role(t, role) for a in actions_of(s)}
    # No model, browser, Gateway, cache or registry access: it only fans out.
    assert not any(a.startswith(("bedrock:", "dynamodb:", "agent-registry:")) for a in actions)
    assert not any("Browser" in a or a == "bedrock-agentcore:InvokeGateway" for a in actions)
    assert "s3:GetObject" not in actions


def test_dispatcher_gets_the_three_specialist_runtime_arns(t):
    env = runtime_of(t, "dispatcher")["Properties"]["EnvironmentVariables"]
    for name in ("url_analyst", "brand_visual", "code_analyst"):
        assert runtime_logical_id(t, name) in json.dumps(env[f"{name.upper()}_RUNTIME_ARN"])
    assert "MODEL_ID" not in env and "BROWSER_ID" not in env


def test_specialist_targets_wait_for_the_gateway_role_policy(t):
    for target in t.find_resources("AWS::BedrockAgentCore::GatewayTarget").values():
        if target["Properties"]["Name"] in ("dispatcher", *SPECIALIST_TARGETS):
            assert any(
                d.startswith("AgentsGatewayRoleDefaultPolicy") for d in target["DependsOn"]
            ), target["Properties"]["Name"]


@pytest.mark.parametrize("registry", [False, True])
def test_harness_reaches_only_the_specialists_gateway(app_context, test_env, registry):
    template = synth(app_context, test_env, agentRegistry=registry)
    harness = next(iter(template.find_resources("AWS::BedrockAgentCore::Harness").values()))
    assert harness["Properties"]["AllowedTools"] == ["@specialists/*"]
    assert len(harness["Properties"]["Tools"]) == 1
    role = role_id(template, "phish orchestrator Harness execution role")
    (gw,) = [s for s in statements_of_role(template, role) if "InvokeGateway" in json.dumps(s)]
    assert gateway_id(template, "phish-specialists") in json.dumps(gw["Resource"])
    assert gateway_id(template, "phish-tools") not in json.dumps(gw["Resource"])


def test_registry_target_is_the_registry_mcp_endpoint_signed_for_agent_registry(reg):
    gateway_id = next(
        lid
        for lid, g in reg.find_resources("AWS::BedrockAgentCore::Gateway").items()
        if g["Properties"]["Name"] == "phish-specialists"
    )
    target = targets_of(reg)["registry"]
    assert gateway_id in json.dumps(target["GatewayIdentifier"])
    endpoint = json.dumps(target["TargetConfiguration"]["Mcp"]["McpServer"]["Endpoint"])
    assert "https://agent-registry." in endpoint and "/mcp" in endpoint
    (provider,) = target["CredentialProviderConfigurations"]
    assert provider["CredentialProviderType"] == "GATEWAY_IAM_ROLE"
    assert provider["CredentialProvider"]["IamCredentialProvider"]["Service"] == "agent-registry"


def test_gateway_role_may_search_only_this_registry(reg):
    role = next(
        lid
        for lid, r in reg.find_resources("AWS::IAM::Role").items()
        if r["Properties"].get("Description")
        == "phish Gateway: SigV4 caller of the specialist tools"
    )
    (search,) = [
        s
        for p in reg.find_resources("AWS::IAM::Policy").values()
        if {"Ref": role} in p["Properties"]["Roles"]
        for s in p["Properties"]["PolicyDocument"]["Statement"]
        if any(a.startswith("agent-registry:") for a in actions_of(s))
    ]
    assert sorted(actions_of(search)) == [
        "agent-registry:InvokeRegistryMcp",
        "agent-registry:SearchDiscoverableRegistryRecords",
    ]
    (registry_id,) = reg.find_resources("AWS::AgentRegistry::Registry")
    assert search["Resource"] == {"Fn::GetAtt": [registry_id, "RegistryArn"]}


def test_harness_waits_for_the_registry_target_and_it_waits_for_the_records(reg):
    harness = next(iter(reg.find_resources("AWS::BedrockAgentCore::Harness").values()))
    targets = reg.find_resources("AWS::BedrockAgentCore::GatewayTarget")
    registry_target = next(
        lid for lid, t in targets.items() if t["Properties"]["Name"] == "registry"
    )
    assert registry_target in harness["DependsOn"]
    deps = set(targets[registry_target]["DependsOn"])
    assert set(reg.find_resources("AWS::AgentRegistry::RegistryRecord")) <= deps
    submits = [lid for lid in reg.find_resources("Custom::AWS") if "Submit" in lid]
    assert len(submits) == 5 and set(submits) <= deps


def test_every_record_is_submitted_for_approval(reg):
    records = reg.find_resources("AWS::AgentRegistry::RegistryRecord")
    submits = [
        r
        for lid, r in reg.find_resources("Custom::AWS").items()
        if "SubmitRegistryRecordForApproval" in json.dumps(r["Properties"])
    ]
    assert len(submits) == len(records) == 5
    text = json.dumps(submits)
    for record_id in records:
        assert f'"{record_id}", "RecordId"' in text, record_id
    assert "ValidationException" in text


def test_no_registry_target_outside_registry_regions(app_context):
    app = cdk.App(context={**app_context, "agentRegistry": True})
    stack = cdk.Stack(app, "S", env=cdk.Environment(account="123456789012", region="eu-central-1"))
    cfg = load_config(app.node)
    data = DataLayer(stack, "Data", cfg=cfg)
    AgentsLayer(stack, "Agents", cfg=cfg, key=data.key, artifacts_bucket=data.artifacts_bucket)
    assert "registry" not in targets_of(Template.from_stack(stack))
