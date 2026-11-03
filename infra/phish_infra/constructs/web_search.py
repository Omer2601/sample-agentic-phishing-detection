# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A small AgentCore Gateway whose only target is the managed Web Search connector.

brand_visual calls it over MCP with SigV4 to confirm a brand's official website, and is the
only role granted InvokeGateway on it. In a Region that offers the connector it lives in the
regional stack; elsewhere in the us-east-1 edge stack, and the regional stack reads its URL and
ARN through a cross-region reference.

Cost: no idle charge. AgentCore Web Search bills $7 per 1,000 queries (AgentCore pricing page,
checked 2026-09-30); brand_visual makes at most 2 per scan, so at most $0.014 per URL.
"""

from __future__ import annotations

from dataclasses import dataclass

import aws_cdk as cdk
from aws_cdk import aws_bedrockagentcore as agentcore
from aws_cdk import aws_iam as iam
from constructs import Construct

from phish_infra.common import agentcore_principal, depend_on_role_policy, stack_output
from phish_infra.config import AppConfig

GATEWAY_SUFFIX = "-web-search"  # phish-web-search for the default appName
# Gateway target names allow letters, digits and single hyphens; the Gateway then names the
# connector's tool {target}___WebSearch.
TARGET_NAME = "web-search"
CONNECTOR_ID = "web-search"
CONNECTOR_TOOL = "WebSearch"
TOOL_NAME = f"{TARGET_NAME}___{CONNECTOR_TOOL}"
# Regions that offered the Web Search connector (AgentCore developer guide, 2026-09-30).
SUPPORTED_REGIONS = ("us-east-1", "eu-west-1", "ap-northeast-1")


@dataclass(frozen=True)
class WebSearchEndpoint:
    """What a consumer in another stack needs: URL to call, ARN to grant, Region to sign for."""

    gateway_url: str
    gateway_arn: str
    region: str
    tool_name: str = TOOL_NAME


def web_search_folds(cfg: AppConfig, region: str | None) -> bool:
    """True when the Web Search Gateway can live in the regional stack.

    Only in a Region that offers the connector. Everywhere else it stays in the us-east-1 edge
    stack.
    """
    return bool(
        cfg.web_search
        and region
        and not cdk.Token.is_unresolved(region)
        and region in SUPPORTED_REGIONS
    )


def add_web_search_target(
    scope: Construct, *, gateway: agentcore.Gateway, role: iam.Role, cfg: AppConfig
) -> agentcore.CfnGatewayTarget:
    """The managed Web Search connector as a target of `gateway`, plus what its role needs."""
    stack = cdk.Stack.of(scope)
    role.add_to_principal_policy(
        iam.PolicyStatement(
            actions=["bedrock-agentcore:InvokeWebSearch"],
            # Service-owned tool ARN: the account field is the literal "aws".
            resources=[
                f"arn:{stack.partition}:bedrock-agentcore:{stack.region}:aws:tool/web-search.v1"
            ],
        )
    )
    # The Web Search service-role policy in the developer guide also lists InvokeGateway on
    # the gateway. A separate policy (not the role's DefaultPolicy) names this gateway's own
    # ARN without a dependency cycle, instead of a gateway/* wildcard.
    self_invoke = iam.Policy(
        scope,
        "GatewaySelfInvoke",
        statements=[
            iam.PolicyStatement(
                actions=["bedrock-agentcore:InvokeGateway"], resources=[gateway.gateway_arn]
            )
        ],
        roles=[role],
    )
    # L1: the aws-cdk-lib 2.271 Gateway L2 has no connector target (add_*_target covers
    # Lambda, OpenAPI, Smithy, API Gateway and MCP server only).
    target = agentcore.CfnGatewayTarget(
        scope,
        "WebSearchTarget",
        gateway_identifier=gateway.gateway_id,
        name=TARGET_NAME,
        description="Managed AgentCore Web Search connector",
        target_configuration=agentcore.CfnGatewayTarget.TargetConfigurationProperty(
            mcp=agentcore.CfnGatewayTarget.McpTargetConfigurationProperty(
                connector=agentcore.CfnGatewayTarget.ConnectorTargetConfigurationProperty(
                    source=agentcore.CfnGatewayTarget.ConnectorSourceProperty(
                        connector_id=CONNECTOR_ID
                    ),
                    configurations=[
                        agentcore.CfnGatewayTarget.ConnectorConfigurationProperty(
                            name=CONNECTOR_TOOL, parameter_values={}
                        )
                    ],
                )
            )
        ),
        # Connector targets accept only the gateway service role as credentials.
        credential_provider_configurations=[
            agentcore.CfnGatewayTarget.CredentialProviderConfigurationProperty(
                credential_provider_type="GATEWAY_IAM_ROLE"
            )
        ],
    )
    target.apply_removal_policy(cfg.removal_policy)
    depend_on_role_policy(target, role)
    target.node.add_dependency(self_invoke)
    return target


class WebSearchGateway(Construct):
    def __init__(self, scope: Construct, id: str, *, cfg: AppConfig) -> None:
        super().__init__(scope, id)
        stack = cdk.Stack.of(self)
        if not cdk.Token.is_unresolved(stack.region) and stack.region not in SUPPORTED_REGIONS:
            raise ValueError(
                f"AgentCore Web Search is not offered in {stack.region}; "
                f"deploy this construct in one of {', '.join(SUPPORTED_REGIONS)}"
            )

        gateway_name = cfg.app_name + GATEWAY_SUFFIX
        role = iam.Role(
            self,
            "GatewayRole",
            assumed_by=agentcore_principal(stack, f"gateway/{gateway_name}"),
            description="phish web search Gateway: calls the AWS-owned Web Search connector",
        )
        gateway = agentcore.Gateway(
            self,
            "Gateway",
            gateway_name=gateway_name,
            description="AgentCore Web Search for the brand_visual specialist",
            # SigV4 inbound: only principals granted InvokeGateway (the brand_visual role) get in.
            authorizer_configuration=agentcore.GatewayAuthorizer.using_aws_iam(),
            protocol_configuration=agentcore.McpProtocolConfiguration(
                supported_versions=[
                    agentcore.MCPProtocolVersion.MCP_2025_03_26,
                    agentcore.MCPProtocolVersion.MCP_2025_06_18,
                ]
            ),
            role=role,
        )
        gateway.apply_removal_policy(cfg.removal_policy)
        add_web_search_target(self, gateway=gateway, role=role, cfg=cfg)

        self.endpoint = WebSearchEndpoint(
            gateway_url=gateway.gateway_url or "",
            gateway_arn=gateway.gateway_arn,
            region=stack.region,
        )
        stack_output(
            self, "WebSearchGatewayUrl", self.endpoint.gateway_url, "Web search Gateway MCP URL"
        )
        stack_output(
            self, "WebSearchGatewayArn", self.endpoint.gateway_arn, "Web search Gateway ARN"
        )
