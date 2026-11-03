# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Console: CloudFront -> Lambda Function URL (Python WSGI + SigV4 proxy) and S3 static assets."""

from __future__ import annotations

import hashlib
import shutil

import aws_cdk as cdk
from aws_cdk import aws_certificatemanager as acm
from aws_cdk import aws_cloudfront as cloudfront
from aws_cdk import aws_cloudfront_origins as origins
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_deployment as s3deploy
from constructs import Construct

from phish_infra.common import (
    BUILD_ROOT,
    REPO_ROOT,
    log_group_prefix,
    run_build_step,
    stack_output,
)
from phish_infra.config import AppConfig
from phish_infra.constructs.api import ROUTES, ScanApi
from phish_infra.constructs.auth import UserAuth
from phish_infra.constructs.data import DataLayer

WEB = REPO_ROOT / "web"
# Lambda Web Adapter layer, published by AWS (an AWS-owned publisher account, not a deployer
# account). In the commercial partition every region uses the same publisher; add a region here
# if AWS publishes it elsewhere. -c lambdaWebAdapterAccount=<id> overrides the lookup for all
# regions (for example another partition), -c lambdaWebAdapterVersion=<n> the pinned version.
LWA_DEFAULT_ACCOUNT = "753240598075"
LWA_LAYER_ACCOUNTS: dict[str, str] = {}
# Pinned: AWS_LWA_* variable names changed in 1.0, so a floating version could break the contract.
LWA_VERSION = "28"


def lwa_layer_account(region: str, override: str | None) -> str:
    if override:
        return str(override)
    if cdk.Token.is_unresolved(region):
        raise ValueError(
            "PhishTriageAgentic needs a concrete region (set CDK_DEFAULT_REGION or AWS_REGION)"
        )
    return LWA_LAYER_ACCOUNTS.get(region, LWA_DEFAULT_ACCOUNT)


def proxy_role_name(cfg: AppConfig) -> str:
    return f"{cfg.app_name}-ui-proxy-{cfg.environment}"


def build_web_bundle(skip: bool) -> tuple[str, str]:
    """(bundle_dir, dist_dir): the web Lambda package and the SPA build for the assets bucket."""
    if skip:
        # A separate tree: writing the stub over the real bundle would keep its .build-id,
        # so the next real synth would reuse the stamp and deploy the stub web tier.
        bundle = BUILD_ROOT / "stub" / "web-bundle"
        dist = bundle / "dist"
        dist.mkdir(parents=True, exist_ok=True)
        (dist / "index.html").write_text("<!doctype html><title>stub</title>\n")
        (bundle / "run.sh").write_text("#!/bin/sh\n")
        return str(bundle), str(dist)
    bundle = BUILD_ROOT / "web-bundle"
    dist = bundle / "dist"
    ignored = {"node_modules", "dist", ".vite", "__pycache__", "devproxy"}
    digest = hashlib.sha256()
    for file in sorted(WEB.rglob("*")):
        if file.is_file() and not ignored & set(file.parts):
            digest.update(str(file.relative_to(WEB)).encode())
            digest.update(file.read_bytes())
    stamp = bundle / ".build-id"
    if stamp.exists() and stamp.read_text() == digest.hexdigest():
        return str(bundle), str(dist)
    shutil.rmtree(bundle, ignore_errors=True)
    bundle.mkdir(parents=True)
    run_build_step(["npm", "ci", "--no-audit", "--no-fund"], WEB)
    run_build_step(["npm", "run", "build"], WEB)
    shutil.copytree(WEB / "dist", dist)
    run_build_step([
        "uv", "pip", "install", "--quiet", "--target", str(bundle),
        "--requirement", str(WEB / "server" / "requirements.txt"),
        "--python-platform", "x86_64-manylinux2014", "--python-version", "3.13",
        "--only-binary", ":all:",
    ])  # fmt: skip
    (bundle / "server").mkdir()
    for src in (WEB / "server").glob("*.py"):
        if not src.name.startswith("test_"):
            shutil.copy2(src, bundle / "server" / src.name)
    shutil.copy2(WEB / "run.sh", bundle / "run.sh")
    (bundle / "run.sh").chmod(0o755)
    stamp.write_text(digest.hexdigest())
    return str(bundle), str(dist)


class WebFrontend(Construct):
    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        cfg: AppConfig,
        api: ScanApi,
        data: DataLayer,
        backend_code: lambda_.Code,
        web_acl_arn: str | None,
    ) -> None:
        super().__init__(scope, id)
        stack = cdk.Stack.of(self)
        name, env = cfg.app_name, cfg.environment
        bundle_dir, dist_dir = build_web_bundle(cfg.skip_asset_build)
        self.proxy_role_name = proxy_role_name(cfg)

        cf_logs = s3.Bucket(
            self,
            "CloudFrontLogs",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=True,
            # CloudFront standard logging writes with ACLs.
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,
            removal_policy=cfg.removal_policy,
            auto_delete_objects=not cfg.is_prod,
            server_access_logs_bucket=data.access_logs_bucket,
            server_access_logs_prefix="cloudfront-logs/",
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="ExpireOldLogs",
                    expiration=cdk.Duration.days(30),
                    noncurrent_version_expiration=cdk.Duration.days(30),
                )
            ],
        )
        assets = s3.Bucket(
            self,
            "Assets",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=True,
            removal_policy=cfg.removal_policy,
            auto_delete_objects=not cfg.is_prod,
            server_access_logs_bucket=data.access_logs_bucket,
            server_access_logs_prefix="assets/",
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="ExpireOldVersions", noncurrent_version_expiration=cdk.Duration.days(30)
                )
            ],
        )

        log_group = logs.LogGroup(
            self,
            "WebLogs",
            log_group_name=f"{log_group_prefix(cfg)}/lambda/Web",
            retention=logs.RetentionDays.ONE_MONTH,
            encryption_key=data.key,
            removal_policy=cfg.removal_policy,
        )
        role = iam.Role(
            self,
            "WebRole",
            role_name=self.proxy_role_name,
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Web tier SigV4 proxy: caller of allowlisted API routes only",
        )
        # Its own log group only, instead of the account-wide AWSLambdaBasicExecutionRole.
        log_group.grant_write(role)
        role.add_to_policy(
            iam.PolicyStatement(
                actions=["execute-api:Invoke"],
                resources=[
                    api.rest_api.arn_for_execute_api(method, path, env) for method, path in ROUTES
                ],
            )
        )

        lwa_account = lwa_layer_account(
            stack.region, self.node.try_get_context("lambdaWebAdapterAccount")
        )
        lwa_version = self.node.try_get_context("lambdaWebAdapterVersion") or LWA_VERSION
        self.web_function = lambda_.Function(
            self,
            "WebFunction",
            function_name=f"{name}-web-{env}",
            description="Console: SPA shell, Cognito code flow, SigV4 proxy to the scan API",
            runtime=lambda_.Runtime.PYTHON_3_13,
            architecture=lambda_.Architecture.X86_64,  # the LWA layer used here is x86
            # LWA execs the handler value; run.sh starts gunicorn on AWS_LWA_PORT.
            handler="run.sh",
            code=lambda_.Code.from_asset(bundle_dir, exclude=["**/__pycache__", "**/*.pyc", "bin"]),
            layers=[
                lambda_.LayerVersion.from_layer_version_arn(
                    self,
                    "Lwa",
                    f"arn:{stack.partition}:lambda:{stack.region}:{lwa_account}"
                    f":layer:LambdaAdapterLayerX86:{lwa_version}",
                )
            ],
            memory_size=1024,
            timeout=cdk.Duration.seconds(60),
            role=role,
            log_group=log_group,
            logging_format=lambda_.LoggingFormat.JSON,
            system_log_level_v2=lambda_.SystemLogLevel.INFO,
            tracing=lambda_.Tracing.ACTIVE,
            environment_encryption=data.key,
            environment={
                "AWS_LAMBDA_EXEC_WRAPPER": "/opt/bootstrap",
                "AWS_LWA_PORT": "8080",
                "AWS_LWA_READINESS_CHECK_PATH": "/healthz",
                # One request per sandbox, so a second worker only doubles memory.
                "GUNICORN_WORKERS": "1",
                "API_BASE_URL": api.base_url,
                "API_REGION": stack.region,
                "APP_ENVIRONMENT": env,
                "DIST_DIR": "/var/task/dist",
                # Below the 60 s function timeout so a slow upstream returns a proxy error.
                "UPSTREAM_TIMEOUT": "55",
                "AUTH_SSM_PREFIX": f"/{name}/{env}/auth",
                # The browser POSTs CSV uploads here; the server adds it to CSP connect-src and
                # form-action.
                "UPLOAD_ORIGIN": data.upload_origin,
                "LOG_LEVEL": "INFO",
            },
        )
        function_url = self.web_function.add_function_url(
            auth_type=lambda_.FunctionUrlAuthType.AWS_IAM
        )
        app_origin = origins.FunctionUrlOrigin.with_origin_access_control(
            function_url,
            read_timeout=cdk.Duration.seconds(60),
            keepalive_timeout=cdk.Duration.seconds(60),
        )
        assets_origin = origins.S3BucketOrigin.with_origin_access_control(
            assets, origin_access_levels=[cloudfront.AccessLevel.READ]
        )

        # A floor for the dynamic behaviours: the application sets CSP and these headers itself,
        # and override=False keeps its values; CloudFront adds them only when a response (an
        # error page, a proxy error) arrives without them.
        app_headers = cloudfront.ResponseHeadersPolicy(
            self,
            "AppSecurityHeaders",
            comment=f"{name} console ({env}): security headers the app may override",
            security_headers_behavior=cloudfront.ResponseSecurityHeadersBehavior(
                strict_transport_security=cloudfront.ResponseHeadersStrictTransportSecurity(
                    access_control_max_age=cdk.Duration.days(730),
                    include_subdomains=True,
                    override=False,
                ),
                content_type_options=cloudfront.ResponseHeadersContentTypeOptions(override=False),
                frame_options=cloudfront.ResponseHeadersFrameOptions(
                    frame_option=cloudfront.HeadersFrameOption.DENY, override=False
                ),
                referrer_policy=cloudfront.ResponseHeadersReferrerPolicy(
                    referrer_policy=cloudfront.HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
                    override=False,
                ),
            ),
        )

        def dynamic(methods: cloudfront.AllowedMethods) -> cloudfront.BehaviorOptions:
            return cloudfront.BehaviorOptions(
                origin=app_origin,
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
                allowed_methods=methods,
                response_headers_policy=app_headers,
                compress=True,
            )

        # Content-hashed bundles from S3; the managed policy restores the security headers
        # S3 does not send.
        static = cloudfront.BehaviorOptions(
            origin=assets_origin,
            viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            allowed_methods=cloudfront.AllowedMethods.ALLOW_GET_HEAD,
            cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
            response_headers_policy=cloudfront.ResponseHeadersPolicy.SECURITY_HEADERS,
            compress=True,
        )
        behaviours = {
            "/assets/*": static,
            "/shield.svg": static,
            "/api/*": dynamic(cloudfront.AllowedMethods.ALLOW_ALL),
            # ALLOW_ALL: POST /auth/register lives here (GET /auth/config and the code flow too).
            "/auth/*": dynamic(cloudfront.AllowedMethods.ALLOW_ALL),
            "/healthz": dynamic(cloudfront.AllowedMethods.ALLOW_GET_HEAD),
        }
        custom_domain: dict = {}
        if cfg.domain_name and cfg.certificate_arn:
            # Only a custom certificate honours the viewer TLS policy; with the default
            # *.cloudfront.net certificate CloudFront ignores it, so it is left unset there.
            custom_domain = {
                "domain_names": [cfg.domain_name],
                "certificate": acm.Certificate.from_certificate_arn(
                    self, "Certificate", cfg.certificate_arn
                ),
                "minimum_protocol_version": cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
            }
        self.distribution = cloudfront.Distribution(
            self,
            "Distribution",
            comment=f"{name} console ({env})",
            # The default behaviour is the function, not the bucket, so an anonymous caller
            # gets a redirect to sign in rather than the app shell (v1 threat T15 control).
            default_behavior=dynamic(cloudfront.AllowedMethods.ALLOW_ALL),
            additional_behaviors=behaviours,
            web_acl_id=web_acl_arn,
            http_version=cloudfront.HttpVersion.HTTP2_AND_3,
            enable_ipv6=True,
            price_class=cloudfront.PriceClass.PRICE_CLASS_100,
            enable_logging=True,
            log_bucket=cf_logs,
            log_file_prefix=f"{name}-cf/",
            log_includes_cookies=False,
            **custom_domain,
        )
        # OAC to a Function URL needs InvokeFunction as well as InvokeFunctionUrl.
        self.web_function.add_permission(
            "CloudFrontInvoke",
            principal=iam.ServicePrincipal("cloudfront.amazonaws.com"),
            action="lambda:InvokeFunction",
            source_arn=(
                f"arn:{stack.partition}:cloudfront::{stack.account}"
                f":distribution/{self.distribution.distribution_id}"
            ),
        )
        deployment = s3deploy.BucketDeployment(
            self,
            "AssetsDeployment",
            sources=[s3deploy.Source.asset(dist_dir)],
            destination_bucket=assets,
            prune=True,
            retain_on_delete=False,
        )
        # The bucket's AutoDeleteObjects resource waits on the bucket policy, which waits on the
        # distribution. Without this edge the SPA lands first, and a rollback in that window
        # cannot delete the non-empty versioned bucket (ROLLBACK_FAILED).
        auto_delete = assets.node.try_find_child("AutoDeleteObjectsCustomResource")
        if auto_delete is not None:
            deployment.node.add_dependency(auto_delete)
        self.url = f"https://{cfg.domain_name or self.distribution.distribution_domain_name}"
        # The batch HTML report links each row back to its scan page in this console.
        api.function.add_environment("CONSOLE_URL", self.url)

        # The browser POSTs CSV uploads straight to S3 (presigned), so large bodies never cross
        # the WAF.
        data.upload_bucket.add_cors_rule(
            allowed_methods=[s3.HttpMethods.POST],
            allowed_origins=[self.url],
            allowed_headers=["*"],
            max_age=3000,
        )

        self.auth = UserAuth(
            self, "Auth", cfg=cfg, key=data.key, public_base_url=self.url, backend_code=backend_code
        )
        self.auth.grant_read(role)
        self.auth.grant_register(role)

        stack_output(self, "WebUrl", self.url, "Open this URL to sign up and scan")
        if cfg.domain_name:
            stack_output(
                self,
                "DistributionDomainName",
                self.distribution.distribution_domain_name,
                f"Point a CNAME (or Route 53 alias) for {cfg.domain_name} at this name",
            )
        stack_output(self, "WebFunctionName", self.web_function.function_name, "Console Lambda")
