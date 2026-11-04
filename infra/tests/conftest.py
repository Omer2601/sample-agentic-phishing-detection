# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json
from pathlib import Path

import aws_cdk as cdk
import pytest

CDK_JSON = Path(__file__).resolve().parents[1] / "cdk.json"


@pytest.fixture(scope="session")
def app_context() -> dict:
    # cdk.App() does not read cdk.json, so feature flags would silently differ
    # from what `cdk deploy` synthesizes. Read the same file the CLI reads.
    context = json.loads(CDK_JSON.read_text())["context"]
    return {**context, "skipAssetBuild": True}


# Every latency flag off: the AgentCore Harness path through the dispatcher and the tools
# Gateway, with one tools Runtime. Tests of that layout pin it here, because the flags are on
# by default since the 2026-11-03 A/B.
LATENCY_OFF = {
    "directOrchestration": "false",
    "localRdap": "false",
    "unanimousFastPath": "false",
    "directSpecialists": "false",
    "directTools": "false",
    "splitToolsRuntimes": "false",
    "latencyBudgets": "false",
    "codeTextBudget": "full",
}


@pytest.fixture(scope="session")
def harness_context(app_context) -> dict:
    return {**app_context, **LATENCY_OFF}


@pytest.fixture(scope="session")
def test_env() -> cdk.Environment:
    # Placeholder account. Never commit a real AWS account id.
    return cdk.Environment(account="123456789012", region="us-west-2")


FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def agent_asset_stubs():
    """Point synth at test-time stubs instead of the agents worktree's prompt and image.

    Tests then neither depend on files another worktree owns nor stage the whole repo as a
    Docker build context for every synth.
    """
    from phish_infra.constructs import agents

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(agents, "ORCHESTRATOR_PROMPT", FIXTURES / "orchestrator_prompt.md")
        mp.setattr(agents, "ORCHESTRATOR_REGISTRY_STEP", FIXTURES / "orchestrator_registry_step.md")
        mp.setattr(agents, "IMAGE_CONTEXT", FIXTURES / "agent_image")
        yield
