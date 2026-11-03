# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_tool_check_accepts_either_container_runtime(monkeypatch):
    pre = load("preflight")
    monkeypatch.setattr(pre, "node_version", lambda: "v22.11.0")
    monkeypatch.setattr(
        pre.shutil, "which", lambda name: "/bin/x" if name in ("uv", "node", "finch") else None
    )
    results = pre.check_tools()
    assert all(r.ok for r in results)


def test_tool_check_fails_without_container_runtime(monkeypatch):
    pre = load("preflight")
    monkeypatch.setattr(pre, "node_version", lambda: "v22.11.0")
    monkeypatch.setattr(
        pre.shutil, "which", lambda name: "/bin/x" if name in ("uv", "node") else None
    )
    assert any(not r.ok and "finch or docker" in r.name for r in pre.check_tools())


def test_node_must_be_22_or_newer(monkeypatch):
    pre = load("preflight")
    assert pre.node_major("v22.11.0") == 22
    assert pre.node_major("garbage") is None


def test_model_access_needs_active_profile_and_authorized_model():
    pre = load("preflight")

    class Bedrock:
        def get_inference_profile(self, inferenceProfileIdentifier):
            return {"status": "ACTIVE"}

        def get_foundation_model_availability(self, modelId):
            return {"authorizationStatus": "AUTHORIZED" if "opus" in modelId else "NOT_AUTHORIZED"}

    results = (
        pre.check_model(Bedrock(), "us.anthropic.claude-opus-5-5"),
        pre.check_model(Bedrock(), "global.anthropic.claude-sonnet-5-5"),
    )
    assert results[0].ok and not results[1].ok
    assert "model access" in results[1].fix


def test_base_model_id_strips_the_geography_prefix():
    pre = load("preflight")
    assert pre.base_model_id("global.anthropic.claude-sonnet-5-5") == "anthropic.claude-sonnet-5-5"
    assert pre.base_model_id("anthropic.claude-sonnet-5-5") == "anthropic.claude-sonnet-5-5"


def test_exit_code():
    pre = load("preflight")
    assert pre.exit_code([pre.Result("a", True, "")]) == 0
    assert pre.exit_code([pre.Result("a", False, "fix")]) == 1


def test_agent_registry_check_passes_outside_its_regions_and_fails_on_denial():
    from botocore.exceptions import ClientError

    preflight = load("preflight")

    class Denied:
        def client(self, *_a, **_k):
            class C:
                def list_registries(self, **_k):
                    raise ClientError(
                        {"Error": {"Code": "AccessDeniedException"}}, "ListRegistries"
                    )

            return C()

    assert preflight.check_agent_registry(Denied(), "eu-central-1").ok
    failed = preflight.check_agent_registry(Denied(), "us-west-2")
    assert not failed.ok and "without -c agentRegistry=true" in failed.fix
