# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The us-east-1 stack: the CloudFront-scoped WAF (CloudFront only accepts web ACLs from
us-east-1) and, with -c webSearch=true, the AgentCore Web Search Gateway for brand_visual."""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_logs as logs
from aws_cdk import aws_wafv2 as wafv2
from constructs import Construct

from phish_infra.common import LOGS_KEY_ACTIONS, apply_tags
from phish_infra.config import AppConfig
from phish_infra.constructs.web_search import WebSearchEndpoint, WebSearchGateway

RATE_LIMIT_PER_5_MIN = 3000
# POST /auth/register creates a Cognito user and sends an email, so it gets its own limit well
# below the general one (10 is the WAF minimum). Cognito's default sender allows 50 emails a day.
REGISTER_PATH = "/auth/register"
REGISTER_LIMIT_PER_5_MIN = 10
# Past the limit WAF answers 429 with this JSON body; web RegisterPage keys on the 429.
REGISTER_BLOCK_BODY_KEY = "too_many_registrations"
REGISTER_BLOCK_BODY = '{"error":"too_many_registrations"}'
# Every *_BODY rule in each group (describe-managed-rule-group, CLOUDFRONT, 2026-09-29).
# If AWS adds a new *_BODY rule to a group, add it here.
COMMON_BODY_RULES = (
    "SizeRestrictions_BODY",
    "EC2MetaDataSSRF_BODY",
    "GenericLFI_BODY",
    "GenericRFI_BODY",
    "CrossSiteScripting_BODY",
)
BAD_INPUT_BODY_RULES = ("JavaDeserializationRCE_BODY", "Log4JRCE_BODY", "ReactJSRCE_BODY")
# Paths as CloudFront sees them. "/api/scan" also matches "/api/scans/{id}" and its retry route.
SCAN_ROUTE_PREFIXES = ("/api/scan", "/api/batches")

W = wafv2.CfnWebACL


def _visibility(metric: str) -> W.VisibilityConfigProperty:
    return W.VisibilityConfigProperty(
        sampled_requests_enabled=True, cloud_watch_metrics_enabled=True, metric_name=metric
    )


def _prefix(path: str) -> W.StatementProperty:
    return W.StatementProperty(
        byte_match_statement=W.ByteMatchStatementProperty(
            field_to_match=W.FieldToMatchProperty(uri_path={}),
            positional_constraint="STARTS_WITH",
            search_string=path,
            text_transformations=[W.TextTransformationProperty(priority=0, type="NONE")],
        )
    )


def _exact(field: W.FieldToMatchProperty, value: str) -> W.StatementProperty:
    return W.StatementProperty(
        byte_match_statement=W.ByteMatchStatementProperty(
            field_to_match=field,
            positional_constraint="EXACTLY",
            search_string=value,
            text_transformations=[W.TextTransformationProperty(priority=0, type="NONE")],
        )
    )


def _register_post() -> W.StatementProperty:
    return W.StatementProperty(
        and_statement=W.AndStatementProperty(
            statements=[
                _exact(W.FieldToMatchProperty(uri_path={}), REGISTER_PATH),
                _exact(W.FieldToMatchProperty(method={}), "POST"),
            ]
        )
    )


def _scan_routes() -> W.StatementProperty:
    return W.StatementProperty(
        or_statement=W.OrStatementProperty(statements=[_prefix(p) for p in SCAN_ROUTE_PREFIXES])
    )


def _not(statement: W.StatementProperty) -> W.StatementProperty:
    return W.StatementProperty(not_statement=W.NotStatementProperty(statement=statement))


def _managed(
    name: str,
    priority: int,
    group: str,
    metric: str,
    *,
    scope_down: W.StatementProperty,
    count_rules: tuple[str, ...] = (),
) -> W.RuleProperty:
    overrides = [
        W.RuleActionOverrideProperty(name=rule, action_to_use=W.RuleActionProperty(count={}))
        for rule in count_rules
    ] or None
    return W.RuleProperty(
        name=name,
        priority=priority,
        override_action=W.OverrideActionProperty(none={}),
        statement=W.StatementProperty(
            managed_rule_group_statement=W.ManagedRuleGroupStatementProperty(
                vendor_name="AWS",
                name=group,
                scope_down_statement=scope_down,
                rule_action_overrides=overrides,
            )
        ),
        visibility_config=_visibility(metric),
    )


class EdgeWafStack(cdk.Stack):
    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        cfg: AppConfig,
        # False when the regional stack folds Web Search into its tools Gateway
        # (web_search_folds), so no second Gateway is deployed here.
        web_search_in_edge: bool = True,
        **kwargs,
    ) -> None:
        super().__init__(scope, id, **kwargs)
        apply_tags(self, cfg)
        prefix = f"{cfg.app_name}-edge"
        scan_routes = _scan_routes()

        # L1: aws-cdk-lib has no L2 for WAFv2.
        # Two instances per managed group put the ACL near 1,800 WCU (limit 5,000).
        acl = W(
            self,
            "WebAcl",
            name=f"{prefix}-waf-{cfg.environment}",
            scope="CLOUDFRONT",
            default_action=W.DefaultActionProperty(allow={}),
            description="Edge protection for the console: rate limit, common rules, bad inputs",
            visibility_config=_visibility(f"{prefix}-waf"),
            custom_response_bodies={
                REGISTER_BLOCK_BODY_KEY: W.CustomResponseBodyProperty(
                    content_type="APPLICATION_JSON", content=REGISTER_BLOCK_BODY
                )
            },
            rules=[
                # Evaluated before the general limit. Block with a JSON 429 rather than Challenge
                # or CAPTCHA: the register form posts with fetch, so it can neither solve a
                # Challenge (202 with an empty body) nor render a CAPTCHA (bare 405 to a non-HTML
                # request). A 429 stops a script just the same and lets the form say why.
                W.RuleProperty(
                    name="RegisterRateLimit",
                    priority=0,
                    action=W.RuleActionProperty(
                        block=W.BlockActionProperty(
                            custom_response=W.CustomResponseProperty(
                                response_code=429,
                                custom_response_body_key=REGISTER_BLOCK_BODY_KEY,
                            )
                        )
                    ),
                    statement=W.StatementProperty(
                        rate_based_statement=W.RateBasedStatementProperty(
                            limit=REGISTER_LIMIT_PER_5_MIN,
                            aggregate_key_type="IP",
                            evaluation_window_sec=300,
                            scope_down_statement=_register_post(),
                        )
                    ),
                    visibility_config=_visibility(f"{prefix}-register-rate-limit"),
                ),
                W.RuleProperty(
                    name="RateLimit",
                    priority=1,
                    action=W.RuleActionProperty(block={}),
                    statement=W.StatementProperty(
                        # 3000 per 5 minutes per IP: one user polling a batch (2 s) and Insights
                        # (5 s) is about 210, so this fits roughly 14 open tabs or a small team
                        # behind one NAT address.
                        rate_based_statement=W.RateBasedStatementProperty(
                            limit=RATE_LIMIT_PER_5_MIN, aggregate_key_type="IP"
                        )
                    ),
                    visibility_config=_visibility(f"{prefix}-rate-limit"),
                ),
                # Two instances per group: full blocking everywhere except the scan routes, and
                # on the scan routes the same group with only its *_BODY rules in Count. A
                # phishing URL in a request body looks like SSRF, LFI or XSS by design, and a
                # blocked scan is a dropped scan.
                _managed(
                    "AWSManagedCommonRuleSet",
                    2,
                    "AWSManagedRulesCommonRuleSet",
                    f"{prefix}-common-rules",
                    scope_down=_not(scan_routes),
                ),
                _managed(
                    "AWSManagedCommonRuleSetScanRoutes",
                    3,
                    "AWSManagedRulesCommonRuleSet",
                    f"{prefix}-common-scan-routes",
                    scope_down=scan_routes,
                    count_rules=COMMON_BODY_RULES,
                ),
                _managed(
                    "AWSManagedKnownBadInputs",
                    4,
                    "AWSManagedRulesKnownBadInputsRuleSet",
                    f"{prefix}-bad-inputs",
                    scope_down=_not(scan_routes),
                ),
                _managed(
                    "AWSManagedKnownBadInputsScanRoutes",
                    5,
                    "AWSManagedRulesKnownBadInputsRuleSet",
                    f"{prefix}-bad-inputs-scan-routes",
                    scope_down=scan_routes,
                    count_rules=BAD_INPUT_BODY_RULES,
                ),
            ],
        )

        # WAF logging requires the aws-waf-logs- prefix. The logs hold request metadata of
        # blocked and counted requests (client IPs, URIs), so they get their own rotating CMK in
        # this region (about 1 USD per month).
        log_group_name = f"aws-waf-logs-{prefix}-{cfg.environment}"
        key = kms.Key(
            self,
            "WafLogsKey",
            alias=f"{prefix}-waf-logs-{cfg.environment}",
            description="Encrypts the CloudFront WAF log group",
            enable_key_rotation=True,
            removal_policy=cfg.removal_policy,
        )
        key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchLogs",
                principals=[iam.ServicePrincipal(f"logs.{self.region}.amazonaws.com")],
                actions=list(LOGS_KEY_ACTIONS),
                # Key policy: KMS requires Resource "*", which here means only this key (it can
                # name no other resource). The condition, not the resource, does the scoping.
                resources=["*"],
                conditions={
                    "ArnLike": {
                        "kms:EncryptionContext:aws:logs:arn": self.format_arn(
                            service="logs",
                            resource="log-group",
                            resource_name=log_group_name,
                            arn_format=cdk.ArnFormat.COLON_RESOURCE_NAME,
                        )
                    }
                },
            )
        )
        log_group = logs.LogGroup(
            self,
            "WafLogGroup",
            log_group_name=log_group_name,
            retention=logs.RetentionDays.ONE_MONTH,
            encryption_key=key,
            removal_policy=cfg.removal_policy,
        )
        wafv2.CfnLoggingConfiguration(
            self,
            "WafLogging",
            resource_arn=acl.attr_arn,
            # WAF wants the log group ARN without the trailing ':*'.
            log_destination_configs=[cdk.Fn.select(0, cdk.Fn.split(":*", log_group.log_group_arn))],
            # Keep only BLOCK and COUNT: those are the requests an operator investigates.
            logging_filter={
                "DefaultBehavior": "DROP",
                "Filters": [
                    {
                        "Behavior": "KEEP",
                        "Requirement": "MEETS_ANY",
                        "Conditions": [
                            {"ActionCondition": {"Action": "BLOCK"}},
                            {"ActionCondition": {"Action": "COUNT"}},
                        ],
                    }
                ],
            },
        )
        self.web_acl_arn = acl.attr_arn
        self.web_search: WebSearchEndpoint | None = (
            WebSearchGateway(self, "WebSearch", cfg=cfg).endpoint
            if cfg.web_search and web_search_in_edge
            else None
        )
        cdk.CfnOutput(
            self,
            "EdgeWebAclArn",
            value=acl.attr_arn,
            description="CLOUDFRONT-scoped web ACL attached to the console distribution",
        )
