# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""CDK entry point: `npx aws-cdk@2.1143.0 deploy --all` from infra/."""

import os

import aws_cdk as cdk

from phish_infra.config import load_config
from phish_infra.constructs.web_search import web_search_folds
from phish_infra.nag import apply_nag
from phish_infra.stacks.edge_waf import EdgeWafStack
from phish_infra.stacks.main import PhishTriageStack

app = cdk.App()
cfg = load_config(app.node)
# Account and region come from the CLI profile; nothing here names an account or region
# except us-east-1, the only region CloudFront accepts web ACLs from. The edge stack also holds
# the AgentCore Web Search Gateway (-c webSearch), offered in us-east-1.
account = os.environ.get("CDK_DEFAULT_ACCOUNT")
region = os.environ.get("CDK_DEFAULT_REGION")
# In a Region that offers Web Search, the regional stack hosts
# the connector on its tools Gateway and the edge stack deploys none.
web_search_folded = web_search_folds(cfg, region)

edge = EdgeWafStack(
    app,
    f"{cfg.stack_prefix}Edge",
    cfg=cfg,
    web_search_in_edge=not web_search_folded,
    env=cdk.Environment(account=account, region="us-east-1"),
    cross_region_references=True,
    description="Phishing triage sample: CloudFront WAF (us-east-1)",
)
main = PhishTriageStack(
    app,
    cfg.stack_prefix,
    cfg=cfg,
    web_acl_arn=edge.web_acl_arn,
    web_search=edge.web_search,  # None when folded into the tools Gateway
    env=cdk.Environment(account=account, region=region),
    cross_region_references=True,
    description="Phishing triage sample: multi-agent URL analysis on Amazon Bedrock AgentCore",
)
apply_nag(app, [edge, main])
app.synth()
