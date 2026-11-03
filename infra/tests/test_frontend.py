# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import aws_cdk as cdk
import pytest
from aws_cdk import aws_lambda as lambda_
from aws_cdk.assertions import Match, Template

from phish_infra.config import load_config
from phish_infra.constructs import frontend
from phish_infra.constructs.agents import AgentsLayer
from phish_infra.constructs.api import ROUTES, ScanApi
from phish_infra.constructs.data import DataLayer
from phish_infra.constructs.frontend import (
    LWA_DEFAULT_ACCOUNT,
    WebFrontend,
    build_web_bundle,
    lwa_layer_account,
    proxy_role_name,
)
from phish_infra.constructs.guardrails import Guardrails
from phish_infra.constructs.pipeline import ScanPipeline


def synth(context, test_env, code_dir):
    app = cdk.App(context=context)
    stack = cdk.Stack(app, "S", env=test_env)
    cfg = load_config(app.node)
    data = DataLayer(stack, "Data", cfg=cfg)
    g = Guardrails(stack, "G", cfg=cfg)
    agents = AgentsLayer(
        stack, "Agents", cfg=cfg, key=data.key, artifacts_bucket=data.artifacts_bucket
    )
    code = lambda_.Code.from_asset(str(code_dir))
    pipeline = ScanPipeline(
        stack, "P", cfg=cfg, data=data, guardrails=g, agents=agents, backend_code=code
    )
    api = ScanApi(
        stack,
        "Api",
        cfg=cfg,
        data=data,
        guardrails=g,
        pipeline=pipeline,
        agents=agents,
        backend_code=code,
        proxy_role_name=proxy_role_name(cfg),
    )
    WebFrontend(stack, "Web", cfg=cfg, api=api, data=data, backend_code=code, web_acl_arn=None)
    return Template.from_stack(stack)


@pytest.fixture(scope="module")
def t(app_context, test_env, tmp_path_factory):
    return synth(app_context, test_env, tmp_path_factory.mktemp("code"))


def test_web_lambda_behind_function_url_with_iam_and_oac(t):
    t.has_resource_properties("AWS::Lambda::Url", {"AuthType": "AWS_IAM"})
    t.resource_count_is("AWS::CloudFront::OriginAccessControl", 2)
    t.has_resource_properties(
        "AWS::Lambda::Permission",
        {"Action": "lambda:InvokeFunction", "Principal": "cloudfront.amazonaws.com"},
    )


def test_web_lambda_env_and_layer(t):
    t.has_resource_properties(
        "AWS::Lambda::Function",
        {
            "FunctionName": "phish-web-dev",
            "Handler": "run.sh",
            "Environment": {
                "Variables": Match.object_like(
                    {
                        "AWS_LAMBDA_EXEC_WRAPPER": "/opt/bootstrap",
                        "AWS_LWA_PORT": "8080",
                        "AUTH_SSM_PREFIX": "/phish/dev/auth",
                        "UPLOAD_ORIGIN": Match.any_value(),
                        "API_BASE_URL": Match.any_value(),
                    }
                )
            },
        },
    )


def test_web_lambda_uses_the_pinned_lwa_layer(t):
    (fn,) = t.find_resources(
        "AWS::Lambda::Function", {"Properties": {"Handler": "run.sh"}}
    ).values()
    layer = str(fn["Properties"]["Layers"])
    assert "753240598075:layer:LambdaAdapterLayerX86:28" in layer
    assert "AWS::Partition" in layer


def test_proxy_role_is_limited_to_the_route_allowlist(t):
    roles = t.find_resources("AWS::IAM::Role", {"Properties": {"RoleName": "phish-ui-proxy-dev"}})
    assert len(roles) == 1
    (role_id,) = roles
    policies = [
        p
        for p in t.find_resources("AWS::IAM::Policy").values()
        if {"Ref": role_id} in p["Properties"]["Roles"]
    ]
    (invoke,) = [
        s
        for p in policies
        for s in p["Properties"]["PolicyDocument"]["Statement"]
        if s["Action"] == "execute-api:Invoke"
    ]
    assert len(invoke["Resource"]) == len(ROUTES)
    text = str(policies)
    assert "cognito-idp:AdminCreateUser" in text  # app mode: POST /auth/register
    assert "ssm:GetParameters" in text


def test_distribution_behaviours_and_logging(t):
    (dist,) = t.find_resources("AWS::CloudFront::Distribution").values()
    config = dist["Properties"]["DistributionConfig"]
    assert config["HttpVersion"] == "http2and3"
    assert config["Logging"]["Bucket"]
    paths = {b["PathPattern"] for b in config["CacheBehaviors"]}
    assert {"/api/*", "/auth/*", "/assets/*", "/shield.svg", "/healthz"} == paths


def test_api_base_url_is_the_stage_url_without_the_deployment(t):
    (fn,) = t.find_resources(
        "AWS::Lambda::Function", {"Properties": {"Handler": "run.sh"}}
    ).values()
    url = str(fn["Properties"]["Environment"]["Variables"]["API_BASE_URL"])
    assert "/dev/" in url and "Deployment" not in url


def test_auth_behaviour_allows_post(t):
    dist = next(iter(t.find_resources("AWS::CloudFront::Distribution").values()))
    behaviours = {
        b["PathPattern"]: b for b in dist["Properties"]["DistributionConfig"]["CacheBehaviors"]
    }
    assert "POST" in behaviours["/auth/*"]["AllowedMethods"]
    assert "/invite" not in behaviours


def test_upload_bucket_cors_allows_only_the_console_origin(t):
    t.has_resource_properties(
        "AWS::S3::Bucket",
        {
            "CorsConfiguration": {
                "CorsRules": [
                    Match.object_like(
                        {"AllowedMethods": ["POST"], "AllowedOrigins": [Match.any_value()]}
                    )
                ]
            }
        },
    )


def test_frontend_outputs_have_exact_keys(t):
    assert {"WebUrl", "WebFunctionName", "UserPoolId", "ManagedLoginUrl"} <= set(
        t.find_outputs("*")
    )


def test_lwa_layer_account_lookup_and_override():
    assert lwa_layer_account("eu-west-1", None) == LWA_DEFAULT_ACCOUNT
    assert lwa_layer_account("eu-west-1", "999999999999") == "999999999999"
    with pytest.raises(ValueError, match="concrete region"):
        lwa_layer_account(cdk.Aws.REGION, None)


CERT = "arn:aws:acm:us-east-1:123456789012:certificate/11111111-2222-3333-4444-555555555555"


def test_default_domain_leaves_the_tls_policy_unset(t):
    # The *.cloudfront.net certificate ignores MinimumProtocolVersion, so it is not set at all.
    (dist,) = t.find_resources("AWS::CloudFront::Distribution").values()
    config = dist["Properties"]["DistributionConfig"]
    assert "ViewerCertificate" not in config and "Aliases" not in config
    assert "DomainName" in str(t.find_outputs("WebUrl"))  # the distribution's own domain


def test_custom_domain_pins_tls_1_2_2021(app_context, test_env, tmp_path):
    t = synth(
        {**app_context, "domainName": "phish.example.com", "certificateArn": CERT},
        test_env,
        tmp_path,
    )
    t.has_resource_properties(
        "AWS::CloudFront::Distribution",
        {
            "DistributionConfig": Match.object_like(
                {
                    "Aliases": ["phish.example.com"],
                    "ViewerCertificate": {
                        "AcmCertificateArn": CERT,
                        "MinimumProtocolVersion": "TLSv1.2_2021",
                        "SslSupportMethod": "sni-only",
                    },
                }
            )
        },
    )
    assert t.find_outputs("WebUrl")["WebUrl"]["Value"] == "https://phish.example.com"
    # Cognito callbacks and the upload CORS origin follow the public URL.
    t.has_resource_properties(
        "AWS::Cognito::UserPoolClient",
        {
            "CallbackURLs": ["https://phish.example.com/auth/callback"],
            "LogoutURLs": ["https://phish.example.com/"],
        },
    )
    assert "DistributionDomainName" in t.find_outputs("*")


def test_dynamic_behaviours_get_security_headers_the_app_can_override(t):
    (policy_id,) = t.find_resources("AWS::CloudFront::ResponseHeadersPolicy")
    t.has_resource_properties(
        "AWS::CloudFront::ResponseHeadersPolicy",
        {
            "ResponseHeadersPolicyConfig": Match.object_like(
                {
                    "SecurityHeadersConfig": {
                        "StrictTransportSecurity": {
                            "AccessControlMaxAgeSec": 63072000,
                            "IncludeSubdomains": True,
                            "Override": False,
                        },
                        "ContentTypeOptions": {"Override": False},
                        "FrameOptions": {"FrameOption": "DENY", "Override": False},
                        "ReferrerPolicy": {
                            "ReferrerPolicy": "strict-origin-when-cross-origin",
                            "Override": False,
                        },
                    }
                }
            )
        },
    )
    (dist,) = t.find_resources("AWS::CloudFront::Distribution").values()
    config = dist["Properties"]["DistributionConfig"]
    dynamic = [config["DefaultCacheBehavior"]] + [
        b for b in config["CacheBehaviors"] if b["PathPattern"] in {"/api/*", "/auth/*", "/healthz"}
    ]
    assert len(dynamic) == 4
    for behaviour in dynamic:
        assert behaviour["ResponseHeadersPolicyId"] == {"Ref": policy_id}


def test_stub_web_bundle_never_touches_the_real_bundle(tmp_path, monkeypatch):
    # Unit tests synth with skip=True. If the stub overwrote the real bundle while its
    # .build-id stayed, the next real synth would reuse the stamp and deploy a stub web tier.
    monkeypatch.setattr(frontend, "BUILD_ROOT", tmp_path)
    real = tmp_path / "web-bundle"
    (real / "dist").mkdir(parents=True)
    (real / "dist" / "index.html").write_text("real spa")
    (real / "run.sh").write_text("real run.sh")
    (real / ".build-id").write_text("digest")
    bundle_dir, dist_dir = build_web_bundle(skip=True)
    assert not bundle_dir.startswith(str(real)) and not dist_dir.startswith(str(real))
    assert (real / "dist" / "index.html").read_text() == "real spa"
    assert (real / "run.sh").read_text() == "real run.sh"
    assert cdk.FileSystem.fingerprint(bundle_dir) and cdk.FileSystem.fingerprint(dist_dir)
