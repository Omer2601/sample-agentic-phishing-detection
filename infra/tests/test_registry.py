# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Registry record payloads must pass the MCP Registry schema the service validates against.

The first live deploy failed with "mcp.server data does not match any supported version"
because the server name had no namespace. The schema is vendored (fixtures/, fetched from
static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json) so the test needs no
network.
"""

import json
import re
from pathlib import Path

import aws_cdk as cdk
import jsonschema
import pytest
from aws_cdk.assertions import Template

from phish_infra.config import load_config
from phish_infra.constructs import registry
from phish_infra.constructs.agents import AgentsLayer
from phish_infra.constructs.data import DataLayer
from phish_infra.constructs.registry import McpRecord, server_payload, tools_payload

SCHEMA = json.loads(
    (Path(__file__).parent / "fixtures" / "mcp-server.schema.2025-12-11.json").read_text()
)
ENDPOINT = "https://bedrock-agentcore.us-west-2.amazonaws.com/runtimes/arn%3Aaws/invocations"
TOOL_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


def record(**over):
    base = {
        "name": "UrlAnalyst",
        "slug": "url-analyst",
        "description": "URL structure, domain reputation and WHOIS analysis",
        "endpoint": ENDPOINT,
        "tools": ({"name": "analyze", "description": "d", "inputSchema": {"type": "object"}},),
    }
    return McpRecord(**{**base, **over})


def validate_server(doc):
    jsonschema.Draft7Validator(SCHEMA).validate(doc)


def validate_tools(doc):
    assert set(doc) == {"tools"} and doc["tools"]
    for tool in doc["tools"]:
        assert TOOL_NAME.match(tool["name"]) and tool["description"]
        assert tool["inputSchema"]["type"] == "object"


def test_schema_version_is_the_documented_one():
    assert registry.SERVER_SCHEMA_VERSION == "2025-12-11"
    assert SCHEMA["$id"].endswith("/2025-12-11/server.schema.json")


def test_server_payload_passes_the_mcp_registry_schema():
    doc = server_payload(record())
    validate_server(doc)
    assert doc["name"] == "com.phishtriage/url-analyst"
    assert doc["remotes"] == [{"type": "streamable-http", "url": ENDPOINT}]


def test_a_bare_name_is_what_the_schema_rejects():
    # The failing deploy's shape: no namespace slash.
    bad = {**server_payload(record()), "name": "UrlAnalyst"}
    with pytest.raises(jsonschema.ValidationError):
        validate_server(bad)


def test_description_over_100_characters_is_refused_before_deploy():
    with pytest.raises(ValueError, match="100"):
        record(description="x" * 101)
    too_long = {**server_payload(record()), "description": "x" * 101}
    with pytest.raises(jsonschema.ValidationError):
        validate_server(too_long)


def test_tools_payload_has_the_tools_list_shape():
    validate_tools(tools_payload(record()))


@pytest.fixture(scope="module")
def template(app_context, test_env):
    app = cdk.App(context={**app_context, "agentRegistry": True})
    stack = cdk.Stack(app, "S", env=test_env)
    cfg = load_config(app.node)
    data = DataLayer(stack, "Data", cfg=cfg)
    AgentsLayer(stack, "Agents", cfg=cfg, key=data.key, artifacts_bucket=data.artifacts_bucket)
    return Template.from_stack(stack)


def flatten(value) -> str:
    """A template string value with every intrinsic replaced by a placeholder URL part."""
    if isinstance(value, str):
        return value
    assert "Fn::Join" in value, value
    sep, parts = value["Fn::Join"]
    return sep.join(p if isinstance(p, str) else "x" for p in parts)


def test_every_synthesized_record_passes_the_schema(template):
    records = template.find_resources("AWS::AgentRegistry::RegistryRecord")
    assert len(records) == 5
    for resource in records.values():
        props = resource["Properties"]
        assert re.fullmatch(r"[A-Za-z0-9]+", props["Name"]), props["Name"]
        server = props["Descriptors"]["McpServer"]
        assert server["DataSchemaVersion"] == "2025-12-11"
        doc = json.loads(flatten(server["Data"]))
        validate_server(doc)
        assert doc["name"].startswith("com.phishtriage/")
        validate_tools(json.loads(flatten(server["AdditionalData"]["Tools"]["Data"])))


def test_server_names_are_unique(template):
    names = [
        json.loads(flatten(r["Properties"]["Descriptors"]["McpServer"]["Data"]))["name"]
        for r in template.find_resources("AWS::AgentRegistry::RegistryRecord").values()
    ]
    assert len(set(names)) == 5
