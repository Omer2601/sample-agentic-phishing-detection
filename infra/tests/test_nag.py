# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json
from pathlib import Path

import aws_cdk as cdk
import pytest

from phish_infra.config import load_config
from phish_infra.nag import IAM5_REASONS, STACK_SUPPRESSIONS, apply_nag
from phish_infra.stacks.edge_waf import EdgeWafStack
from phish_infra.stacks.main import PhishTriageStack


def nag_findings(assembly: cdk.cx_api.CloudAssembly) -> list[str]:
    """AwsSolutions errors and warnings from the synthesized metadata.

    Read from the assembly files because Annotations.find_error cannot marshal its results
    through jsii in Python (Unknown interface cloud_assembly_schema.MetadataEntry).
    """
    root = Path(assembly.directory)
    manifest = json.loads((root / "manifest.json").read_text())
    findings = []
    for artifact in manifest["artifacts"].values():
        metadata = artifact.get("metadata") or {}
        if artifact.get("additionalMetadataFile"):
            metadata = json.loads((root / artifact["additionalMetadataFile"]).read_text())
        for path, entries in metadata.items():
            for entry in entries:
                data = str(entry.get("data"))
                if entry["type"] in {"aws:cdk:error", "aws:cdk:warning"} and data.startswith(
                    "AwsSolutions-"
                ):
                    findings.append(f"{path}: {data[:300]}")
    return findings


@pytest.mark.parametrize(
    "extra",
    [
        {},
        {"agentRegistry": True},
        {"webSearch": "false"},
        {"inviteCode": True},
        {"signUpMode": "cognito", "allowedEmailDomains": "example.com"},
        {"mfa": "required", "cognitoPlan": "plus"},
        {
            "domainName": "phish.example.com",
            "certificateArn": (
                "arn:aws:acm:us-east-1:123456789012:certificate/"
                "11111111-2222-3333-4444-555555555555"
            ),
        },
    ],
)
def test_no_unsuppressed_nag_findings(app_context, extra):
    app = cdk.App(context={**app_context, **extra})
    cfg = load_config(app.node)
    edge = EdgeWafStack(
        app,
        "Edge",
        cfg=cfg,
        env=cdk.Environment(account="123456789012", region="us-east-1"),
        cross_region_references=True,
    )
    main = PhishTriageStack(
        app,
        "Main",
        cfg=cfg,
        web_acl_arn=edge.web_acl_arn,
        web_search=edge.web_search,
        env=cdk.Environment(account="123456789012", region="us-west-2"),
        cross_region_references=True,
    )
    apply_nag(app, [edge, main])
    findings = nag_findings(app.synth())
    assert findings == [], "\n".join(findings)


def test_every_suppression_has_a_reason():
    for suppression in STACK_SUPPRESSIONS:
        assert len(suppression.reason) >= 20, suppression.id
    iam = [s for s in STACK_SUPPRESSIONS if s.id in {"AwsSolutions-IAM4", "AwsSolutions-IAM5"}]
    assert all(s.applies_to for s in iam), "IAM suppressions must name what they apply to"
    for pattern, reason in IAM5_REASONS.items():
        assert pattern and len(reason) >= 20, pattern
