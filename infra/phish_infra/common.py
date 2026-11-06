# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Helpers shared by every construct: tags, Bedrock ARNs, Lambda defaults and asset builds."""

from __future__ import annotations

import hashlib
import shutil
import subprocess  # nosec B404: fixed argv lists, no shell, used only for synth-time asset builds
from collections.abc import Mapping, Sequence
from pathlib import Path

import aws_cdk as cdk
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from constructs import Construct, IConstruct

from phish_infra.config import AppConfig

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_ROOT = REPO_ROOT / "build"
_PROFILE_PREFIXES = ("us.", "eu.", "apac.", "au.", "jp.", "global.")
# What CloudWatch Logs calls on a log group CMK, as explicit actions (no wildcards), so the
# key policy grants no action the service never uses (for example GenerateDataKeyPair).
LOGS_KEY_ACTIONS = (
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:ReEncryptFrom",
    "kms:ReEncryptTo",
    "kms:GenerateDataKey",
    "kms:GenerateDataKeyWithoutPlaintext",
    "kms:DescribeKey",
)


def standard_tags(cfg: AppConfig) -> dict[str, str]:
    return {"Project": "phish-triage", "Owner": cfg.owner, "Environment": cfg.environment}


def apply_tags(scope: IConstruct, cfg: AppConfig) -> None:
    for key, value in standard_tags(cfg).items():
        cdk.Tags.of(scope).add(key, value)


def cfn_tag_list(cfg: AppConfig) -> list[dict[str, str]]:
    """Tags for a raw CfnResource, which the Tags aspect cannot reach."""
    return [{"Key": key, "Value": value} for key, value in standard_tags(cfg).items()]


def foundation_model_id(model_id: str) -> str:
    for prefix in _PROFILE_PREFIXES:
        if model_id.startswith(prefix):
            return model_id[len(prefix) :]
    return model_id


BEDROCK_INVOKE_ACTIONS = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]


def bedrock_invoke_statements(
    scope: Construct, model_ids: Sequence[str]
) -> list[iam.PolicyStatement]:
    """InvokeModel on inference profiles in this Region and the models they route to.

    The Converse and ConverseStream APIs authorize with these same two actions. A
    cross-region profile is invoked in this Region but served from several, so its
    foundation-model ARNs need a Region wildcard; the bedrock:InferenceProfileArn
    condition limits that wildcard to calls made through this stack's profiles.
    """
    stack = cdk.Stack.of(scope)
    direct: list[str] = []
    profiles: list[str] = []
    routed: list[str] = []
    for model_id in dict.fromkeys(model_ids):
        base = foundation_model_id(model_id)
        if base == model_id:
            direct.append(f"arn:{stack.partition}:bedrock:{stack.region}::foundation-model/{base}")
            continue
        profiles.append(
            f"arn:{stack.partition}:bedrock:{stack.region}:{stack.account}"
            f":inference-profile/{model_id}"
        )
        routed.append(f"arn:{stack.partition}:bedrock:*::foundation-model/{base}")
        if model_id.startswith("global."):
            # Global profiles also authorize against the region-less model ARN.
            routed.append(f"arn:{stack.partition}:bedrock:::foundation-model/{base}")
    statements = [iam.PolicyStatement(actions=BEDROCK_INVOKE_ACTIONS, resources=profiles + direct)]
    if routed:
        statements.append(
            iam.PolicyStatement(
                actions=BEDROCK_INVOKE_ACTIONS,
                resources=routed,
                conditions={"StringEquals": {"bedrock:InferenceProfileArn": profiles}},
            )
        )
    return statements


def agentcore_principal(stack: cdk.Stack, *resources: str) -> iam.ServicePrincipal:
    # Confused-deputy guard: only the named AgentCore resources in this account may assume the
    # role. A prefix wildcard because the service appends an id to the name in the ARN, and the
    # ARN attribute cannot be referenced here (the resource depends on this role).
    arns = [
        f"arn:{stack.partition}:bedrock-agentcore:{stack.region}:{stack.account}:{resource}*"
        for resource in resources
    ]
    return iam.ServicePrincipal(
        "bedrock-agentcore.amazonaws.com",
        conditions={
            "StringEquals": {"aws:SourceAccount": stack.account},
            "ArnLike": {"aws:SourceArn": arns[0] if len(arns) == 1 else arns},
        },
    )


def depend_on_role_policy(dependent: Construct, role: iam.IRole) -> None:
    """Order a resource after the role's DefaultPolicy so the service never sees a half-granted
    role."""
    policy = role.node.try_find_child("DefaultPolicy")
    if policy is not None:
        dependent.node.add_dependency(policy)


# The only programs an asset build starts.
BUILD_TOOLS = frozenset({"uv", "npm"})


def run_build_step(cmd: list[str], cwd: Path = REPO_ROOT) -> None:
    """Run one asset build command. The only place the CDK app starts a process.

    uv and npm have no Python API, so a process is the only way. Each argv is a list that
    starts with a literal member of BUILD_TOOLS, never a shell string: callers choose
    arguments but never the executable, and shell metacharacters in an argument stay literal.
    """
    program, *args = cmd
    try:
        match program:
            case "uv":
                subprocess.run(["uv", *args], cwd=cwd, check=True)  # noqa: S603, S607  # nosec B603 B607: fixed argv, literal program resolved from PATH on purpose, no shell, no untrusted input
            case "npm":
                subprocess.run(["npm", *args], cwd=cwd, check=True)  # noqa: S603, S607  # nosec B603 B607: fixed argv, literal program resolved from PATH on purpose, no shell, no untrusted input
            case _:
                raise RuntimeError(f"Asset build: {program} is not an allowed build tool")
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"Asset build failed: `{' '.join(cmd)}` in {cwd}: {exc}") from exc


def build_python_asset(
    name: str, *, package: str | None, sources: Mapping[str, Path], platform: str, skip: bool
) -> str:
    """Build a Lambda code directory: pinned third-party wheels plus workspace sources.

    Rebuilt only when uv.lock or a source file changes, so repeated synths are fast.
    """
    out = BUILD_ROOT / name
    if skip:
        # Kept apart from the real asset so a stub never lands in a deployed package.
        out = BUILD_ROOT / "stub" / name
        out.mkdir(parents=True, exist_ok=True)
        (out / "stub.py").write_text("# unit-test stub asset\n")
        return str(out)

    digest = hashlib.sha256((REPO_ROOT / "uv.lock").read_bytes() + platform.encode())
    for dest, src in sorted(sources.items()):
        if not src.is_dir():
            raise FileNotFoundError(f"Lambda source directory missing: {src}")
        digest.update(dest.encode())
        for file in sorted(src.rglob("*")):
            if file.is_file() and "tests" not in file.parts and "__pycache__" not in file.parts:
                digest.update(str(file.relative_to(REPO_ROOT)).encode())
                digest.update(file.read_bytes())
    stamp = out / ".build-id"
    if stamp.exists() and stamp.read_text() == digest.hexdigest():
        return str(out)

    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    if package:
        requirements = BUILD_ROOT / f"{name}-requirements.txt"
        run_build_step([
            "uv", "export", "--package", package, "--no-dev", "--frozen", "--no-hashes",
            "--no-emit-workspace", "--no-emit-project", "-o", str(requirements),
        ])  # fmt: skip
        run_build_step([
            "uv", "pip", "install", "--quiet", "--target", str(out),
            "--requirement", str(requirements), "--python-platform", platform,
            "--python-version", "3.13", "--only-binary", ":all:",
        ])  # fmt: skip
    for dest, src in sources.items():
        shutil.copytree(
            src,
            out / dest,
            ignore=shutil.ignore_patterns("tests", "__pycache__", "*.pyc"),
            dirs_exist_ok=True,
        )
    stamp.write_text(digest.hexdigest())
    return str(out)


def log_group_prefix(cfg: AppConfig) -> str:
    """Prefix of every Lambda log group in the stack, e.g. /phish/dev."""
    return f"/{cfg.app_name}/{cfg.environment}"


def python_function(
    scope: Construct,
    id: str,
    *,
    cfg: AppConfig,
    key: kms.IKey,
    code: lambda_.Code,
    handler: str,
    description: str,
    environment: Mapping[str, str],
    timeout: cdk.Duration,
    memory_mb: int = 512,
) -> lambda_.Function:
    log_group = logs.LogGroup(
        scope,
        f"{id}Logs",
        # Named under the stack's log prefix so the data key's CloudWatch Logs grant can name
        # this stack's log groups instead of every log group in the account.
        log_group_name=f"{log_group_prefix(cfg)}/lambda/{id}",
        retention=logs.RetentionDays.ONE_MONTH,
        encryption_key=key,
        removal_policy=cfg.removal_policy,
    )
    # No logs:CreateLogGroup (AWSLambdaBasicExecutionRole grants it on *): once CloudFormation
    # deletes the group, the runtime cannot recreate it under the name the next deployment
    # creates. Inline, so the role depends on the group and goes before it on delete.
    role = iam.Role(
        scope,
        f"{id}Role",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        inline_policies={
            "Logs": iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                        resources=[log_group.log_group_arn],
                    )
                ]
            )
        },
    )
    return lambda_.Function(
        scope,
        id,
        runtime=lambda_.Runtime.PYTHON_3_13,
        architecture=lambda_.Architecture.ARM_64,
        handler=handler,
        code=code,
        description=description,
        timeout=timeout,
        memory_size=memory_mb,
        environment={"LOG_LEVEL": "INFO", **environment},
        environment_encryption=key,
        log_group=log_group,
        role=role,
        logging_format=lambda_.LoggingFormat.JSON,
        system_log_level_v2=lambda_.SystemLogLevel.INFO,
        tracing=lambda_.Tracing.ACTIVE,
    )


def stack_output(scope: Construct, name: str, value: str, description: str = "") -> cdk.CfnOutput:
    """A stack output whose OutputKey is exactly `name`, wherever the construct sits.

    Scripts and the other packages read outputs by key (plans/interfaces.md, Stack outputs);
    CDK would otherwise prefix and hash the logical id of an output inside a construct.
    """
    output = cdk.CfnOutput(scope, name, value=value, description=description or None)
    output.override_logical_id(name)
    return output
