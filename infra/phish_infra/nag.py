# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""cdk-nag AwsSolutions checks with every accepted exception written down with its reason.

Rule of thumb: narrow the policy in the construct first. A suppression is only for a wildcard
the service or a CDK-managed construct requires, and IAM4/IAM5 suppressions always carry
`applies_to`, so a new wildcard fails the test instead of hiding behind an old reason.
"""

from __future__ import annotations

import aws_cdk as cdk
from cdk_nag import AwsSolutionsChecks, NagPackSuppression, NagSuppressions

_MANAGED_LOGGING_POLICIES = (
    "/^Policy::arn:<AWS::Partition>:iam::aws:policy\\/service-role\\/"
    "(AWSLambdaBasicExecutionRole|AmazonAPIGatewayPushToCloudWatchLogs)$/g"
)

STACK_SUPPRESSIONS = [
    NagPackSuppression(
        id="AwsSolutions-APIG3",
        reason=(
            "Every route but /health requires IAM SigV4, the resource policy limits callers to "
            "this account, and the stage is throttled. The console path is covered by the "
            "CloudFront WAF; a regional WAF adds no control an IAM-only API needs."
        ),
    ),
    NagPackSuppression(
        id="AwsSolutions-APIG4",
        reason=(
            'Only GET /health has no authorizer: a liveness probe that returns {"ok": true} '
            "and no data. Every other route uses AuthorizationType IAM."
        ),
    ),
    NagPackSuppression(
        id="AwsSolutions-COG4",
        reason=(
            "The API authenticates with IAM SigV4 (the console proxy role or a caller's own "
            "principal), not a Cognito authorizer; the proxy verifies the Cognito session."
        ),
    ),
    NagPackSuppression(
        id="AwsSolutions-COG2",
        reason=(
            "Only with the default -c mfa=optional: TOTP is offered to every user but not "
            "forced, a sample-usability choice. Deploy with -c mfa=required to force it (then "
            "this check passes). Sign-up is gated by an emailed temporary password, the WAF "
            "register rate limit and the optional invite code."
        ),
    ),
    NagPackSuppression(
        id="AwsSolutions-COG8",
        reason=(
            "Only with the default -c cognitoPlan=essentials: PLUS (threat protection) has no "
            "free tier. Deploy with -c cognitoPlan=plus for the PLUS plan with threat protection "
            "enforced (then this check passes)."
        ),
    ),
    NagPackSuppression(
        id="AwsSolutions-IAM4",
        reason=(
            "AWS managed baseline logging policies only (AWSLambdaBasicExecutionRole on "
            "CDK-created function roles, AmazonAPIGatewayPushToCloudWatchLogs on the API "
            "Gateway account role)."
        ),
        applies_to=[{"regex": _MANAGED_LOGGING_POLICIES}],
    ),
    NagPackSuppression(
        id="AwsSolutions-CFR1",
        reason=(
            "No geo restriction: the sample console is meant to be reachable from any region. "
            "Add one for a production audience."
        ),
    ),
    NagPackSuppression(
        id="AwsSolutions-CFR4",
        reason=(
            "Only without -c domainName/-c certificateArn: the default *.cloudfront.net "
            "certificate ignores the viewer TLS policy. With a custom domain and its ACM "
            "certificate the distribution pins TLSv1.2_2021 and this check passes."
        ),
    ),
    NagPackSuppression(
        id="AwsSolutions-L1",
        reason=(
            "Functions pin python3.13, the interpreter the uv workspace and its locked wheels "
            "target; CDK-managed singleton functions run the runtime CDK chooses."
        ),
    ),
    NagPackSuppression(
        id="AwsSolutions-SMG4",
        reason=(
            "The optional invite code is a shared value read on demand; rotating means "
            "replacing the value, which takes effect immediately. No database credential."
        ),
    ),
    NagPackSuppression(
        id="AwsSolutions-SQS3",
        reason=(
            "The stats stream DLQ and the batch DLQ are themselves dead-letter destinations "
            "(the DynamoDB stream event source's and the splitter's async on-failure "
            "targets), and each has an alarm when not empty."
        ),
    ),
]

# Keys are literal substrings of the IAM5 finding (escaped into a regex below).
IAM5_REASONS = {
    "Resource::*": (
        "Only actions without resource-level permissions: X-Ray PutTraceSegments, "
        "PutTelemetryRecords and GetSampling*, ecr:GetAuthorizationToken, dynamodb:ListStreams, "
        "and cloudwatch:PutMetricData (limited by a cloudwatch:namespace condition)."
    ),
    ":bedrock:*:": (
        "Cross-region and global inference profiles are served from several regions, so the "
        "profile and foundation-model ARNs carry a region wildcard; the model id is fixed."
    ),
    "/index/*": "Queries use the table GSIs, whose ARNs are the table ARN plus /index/<name>.",
    "/scans/*": (
        "Artifacts and findings are keyed by scan id at runtime; bounded to the scans/ prefix "
        "of the artifacts bucket."
    ),
    "/batches/*/report.html": (
        "Batch HTML reports are keyed by batch id at runtime; bounded to one object name under "
        "the batches/ prefix of the artifacts bucket."
    ),
    "/uploads/*": "Upload keys contain the batch id at runtime; bounded to uploads/ of one bucket.",
    "browser-session/*": (
        "Browser session ids are minted per scan; bounded to this account's sessions of the "
        "AWS-managed browser."
    ),
    "runtime-endpoint/*": (
        "InvokeAgentRuntime also authorizes the runtime endpoint ARN; endpoints are "
        "service-named under the three runtimes in this stack."
    ),
    # memory/<appName>_orchestrator-* and harness/<appName>_orchestrator-*.
    "_orchestrator-*": (
        "The harness ARN and its managed memory ARN carry a service-generated suffix "
        "(Phase 0 spike)."
    ),
    "log-group:/aws/bedrock-agentcore/": (
        "AgentCore writes to log groups it names under the harness or runtime prefix, with a "
        "generated suffix and per-session streams."
    ),
    "log-group:*": (
        "logs:DescribeLogGroups (granted by the Runtime L2) only supports the account-level "
        "log-group wildcard."
    ),
    "workload-identity/*": (
        "Runtime workload identities are created and named by the service (Runtime L2 grant)."
    ),
    ":execute-api:": (
        "The path wildcard stands for the {id} path parameter of one method on this API and "
        "stage; every route is listed explicitly."
    ),
    "cdk-hnb659fds-assets-": "CDK BucketDeployment reads its source zip from the bootstrap bucket.",
    "WebAssets": "CDK BucketDeployment syncs the SPA build into the console assets bucket.",
    "Arn>:*": "Lambda grant_invoke covers the function's versions and aliases (ARN plus :*).",
    "Action::kms:ReEncrypt*": "CDK grant helpers use ReEncrypt* on one key (the data CMK).",
    "Action::kms:GenerateDataKey*": "CDK grant helpers use GenerateDataKey* on the data CMK.",
    "Action::s3:GetObject*": "CDK BucketDeployment grant on the bootstrap and assets buckets.",
    "Action::s3:GetBucket*": "CDK BucketDeployment grant on the bootstrap and assets buckets.",
    "Action::s3:List*": "CDK BucketDeployment grant on the bootstrap and assets buckets.",
    "Action::s3:DeleteObject*": "CDK BucketDeployment prunes old SPA files in the assets bucket.",
    "Action::s3:Abort*": "CDK BucketDeployment grant on the console assets bucket.",
}


def apply_nag(app: cdk.App, stacks: list[cdk.Stack]) -> None:
    cdk.Aspects.of(app).add(AwsSolutionsChecks(verbose=True, reports=True))
    for stack in stacks:
        NagSuppressions.add_stack_suppressions(stack, STACK_SUPPRESSIONS)
        NagSuppressions.add_stack_suppressions(
            stack,
            [
                NagPackSuppression(
                    id="AwsSolutions-IAM5",
                    reason=reason,
                    applies_to=[{"regex": f"/{_escape(pattern)}/g"}],
                )
                for pattern, reason in IAM5_REASONS.items()
            ],
        )


def _escape(pattern: str) -> str:
    return "".join("\\" + c if c in r".*+?^$()[]{}|/\\" else c for c in pattern)
