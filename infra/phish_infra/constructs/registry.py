# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AWS Agent Registry catalog of the phish MCP servers (-c agentRegistry=true, off by default).

What this is, and is not. The registry is the discovery and governance layer: each MCP server
(the dispatcher, the three specialists and the shared tools server) is a record with its
endpoint and tool definitions, approved automatically in this sample. It does not route calls.
AgentCore Gateway has no documented target type that reads a registry record (checked against
the AgentCore developer guide, 2026-10-05), and the registry's own MCP endpoint only exposes the
three discovery tools (search, list and batch-get of records). The orchestrator reaches that
endpoint as one more MCP server target (`registry`) on its own Gateway and searches it at the
start of every scan; invocation stays on the Gateway's own targets (round one is still one
dispatcher call), so a record can only tell the model which of the Gateway's own tools exist,
never add an endpoint.

Cost: no idle charge found for the registry at the time of writing; verify on the AgentCore
pricing page before leaving it deployed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import aws_cdk as cdk
from aws_cdk import aws_agentregistry as registry
from aws_cdk import aws_iam as iam
from aws_cdk import custom_resources as cr
from constructs import Construct

from phish_infra.common import stack_output
from phish_infra.config import AppConfig

REGISTRY_SUFFIX = "Specialists"  # PhishSpecialists for the default appName
# Agent Registry is offered in these Regions (GA 2026-08-31 announcement).
SUPPORTED_REGIONS = ("us-west-2", "us-east-1")
RECORD_VERSION = "1.0.0"
# The record payload is validated against the official MCP Registry server.json schema. This
# is the version the Agent Registry developer guide uses in its create-registry-record example
# ("dataSchemaVersion": "2025-12-11"); naming it stops the service guessing a version and
# failing with "data does not match any supported version".
SERVER_SCHEMA_VERSION = "2025-12-11"
# server.json "name" is reverse-DNS namespace, one slash, server name. The namespace is only an
# identifier inside this private registry; it is not looked up.
SERVER_NAMESPACE = "com.phishtriage"
# server.json caps "description" at 100 characters.
SERVER_DESCRIPTION_MAX = 100
# The registry MCP endpoint is signed for this service name (registry-mcp-endpoint.html,
# "aws:amz:<region>:agent-registry").
SIGV4_SERVICE = "agent-registry"
# AWS SDK for JavaScript v3 client for SubmitRegistryRecordForApproval. Agent Registry went GA
# on 2026-08-31, so the Lambda runtime's bundled SDK may predate it; the custom resource installs
# the latest SDK instead (one npm install on a cold start).
CONTROL_SDK = "@aws-sdk/client-agent-registry-control"


@dataclass(frozen=True)
class McpRecord:
    """One MCP server to catalog. `endpoint` may be a CDK token."""

    name: str  # alphanumeric: the CloudFormation record name
    slug: str  # server.json name part, for example "url-analyst"
    description: str  # at most SERVER_DESCRIPTION_MAX characters
    endpoint: str
    tools: tuple[dict[str, Any], ...]

    def __post_init__(self) -> None:
        if not 1 <= len(self.description) <= SERVER_DESCRIPTION_MAX:
            raise ValueError(
                f"{self.name}: description must be 1 to {SERVER_DESCRIPTION_MAX} characters "
                f"(MCP server.json limit), got {len(self.description)}"
            )


def server_payload(record: McpRecord) -> dict[str, Any]:
    """The server.json document (schema 2025-12-11) for one record.

    No "$schema" key: the Agent Registry guide's own example omits it and passes the version in
    dataSchemaVersion instead.
    """
    return {
        "name": f"{SERVER_NAMESPACE}/{record.slug}",
        "description": record.description,
        "version": RECORD_VERSION,
        "remotes": [{"type": "streamable-http", "url": record.endpoint}],
    }


def tools_payload(record: McpRecord) -> dict[str, Any]:
    """The tools definition in the shape of an MCP tools/list result."""
    return {"tools": list(record.tools)}


class SpecialistRegistry(Construct):
    def __init__(
        self, scope: Construct, id: str, *, cfg: AppConfig, records: list[McpRecord]
    ) -> None:
        super().__init__(scope, id)
        stack = cdk.Stack.of(self)
        # Tags come from the stack-level Tags aspect (both resources are taggable).
        # L1: aws-cdk-lib 2.271 ships only CfnRegistry and CfnRegistryRecord for
        # AWS::AgentRegistry (no L2 before 2.272), so the properties are set directly.
        self.registry = registry.CfnRegistry(
            self,
            "Registry",
            name=cfg.app_name.capitalize() + REGISTRY_SUFFIX,
            description="Catalog of the phish triage MCP servers",
            # SigV4 for consumers: no identity provider to run for a sample. CUSTOM_JWT is the
            # choice when consumers outside AWS need to search it.
            authorizer_type="AWS_IAM",
            # Records would otherwise wait in PENDING_APPROVAL for a human. The records here
            # are published by this stack from the same repo, so approval adds no control.
            approval_configuration=registry.CfnRegistry.ApprovalConfigurationProperty(
                auto_approval_rules=["APPROVE_ALL"]
            ),
        )
        self.registry.apply_removal_policy(cfg.removal_policy)
        self.records = [self._record(stack, record, cfg) for record in records]
        self.registry_arn = self.registry.attr_registry_arn
        self.registry_id = self.registry.attr_registry_id
        self.mcp_url = cdk.Fn.join(
            "",
            [
                "https://agent-registry.",
                stack.region,
                ".api.aws/registry/",
                self.registry_id,
                "/mcp",
            ],
        )
        stack_output(self, "RegistryArn", self.registry_arn, "Agent Registry ARN")
        stack_output(
            self, "RegistryMcpUrl", self.mcp_url, "Registry MCP endpoint (search_discoverable_*)"
        )

    def _record(
        self, stack: cdk.Stack, record: McpRecord, cfg: AppConfig
    ) -> registry.CfnRegistryRecord:
        server = stack.to_json_string(server_payload(record))
        tools = stack.to_json_string(tools_payload(record))
        resource = registry.CfnRegistryRecord(
            self,
            f"{record.name}Record",
            registry_id=self.registry.attr_registry_id,
            name=record.name,
            display_name=record.name,
            description=record.description,
            record_type="MCP",
            record_version=RECORD_VERSION,
            descriptors=registry.CfnRegistryRecord.DescriptorsProperty(
                mcp_server=registry.CfnRegistryRecord.McpServerDescriptorProperty(
                    data=server,
                    data_schema_version=SERVER_SCHEMA_VERSION,
                    additional_data=registry.CfnRegistryRecord.McpServerAdditionalDataProperty(
                        tools=registry.CfnRegistryRecord.McpToolsDescriptorProperty(data=tools)
                    ),
                )
            ),
        )
        resource.apply_removal_policy(cfg.removal_policy)
        self._submit(record.name, resource)
        return resource

    def _submit(self, name: str, resource: registry.CfnRegistryRecord) -> None:
        """Move the record from DRAFT into the approval workflow, where APPROVE_ALL approves it.

        CloudFormation creates records as DRAFT and Status is read-only, so without this no
        record is ever discoverable and every search returns nothing (seen live 2026-10-16).
        `clientUpdatedAt` is not an API member (the SDK drops unknown input keys); it carries the
        record's updatedAt so a changed record changes this resource and is submitted again.
        A record that is still
        APPROVED after an update rejects a second submit with ValidationException ("Cannot
        submit the record for approval in current status: APPROVED"), which is the state this
        resource exists to reach, so that one error code is ignored.
        """
        call = cr.AwsSdkCall(
            service=CONTROL_SDK,
            action="SubmitRegistryRecordForApproval",
            parameters={
                "registryId": self.registry.attr_registry_id,
                "recordId": resource.attr_record_id,
                "clientUpdatedAt": resource.attr_updated_at,
            },
            physical_resource_id=cr.PhysicalResourceId.of(resource.attr_record_id),
            ignore_error_codes_matching="ValidationException",
        )
        cr.AwsCustomResource(
            self,
            f"{name}Submit",
            on_create=call,
            on_update=call,
            policy=cr.AwsCustomResourcePolicy.from_statements(
                [
                    iam.PolicyStatement(
                        actions=["agent-registry:SubmitRegistryRecordForApproval"],
                        resources=[resource.attr_record_arn],
                    )
                ]
            ),
            install_latest_aws_sdk=True,
        )

    def grant_discovery(self, grantee: iam.IGrantable) -> None:
        """Let a principal search this registry and call its MCP endpoint (SigV4)."""
        iam.Grant.add_to_principal(
            grantee=grantee,
            actions=[
                "agent-registry:InvokeRegistryMcp",
                "agent-registry:SearchDiscoverableRegistryRecords",
            ],
            resource_arns=[self.registry_arn],
        )
