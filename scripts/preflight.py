# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Pre-deployment checks for any AWS account and region.

Model access, AgentCore availability and CDK bootstrap cannot be provisioned by the
stack, and each otherwise fails late (model access fails at the first scan, which
looks like a broken app). This turns them into a fast pass or fail with a fix.

Usage:
    uv run --package phish-backend python scripts/preflight.py --profile <name> --region <region>
Exit codes: 0 ready, 1 blocking problems, 2 could not run the checks.
"""

import argparse
import logging
import re
import shutil
import subprocess  # nosec B404: fixed argv lists, no shell, used only to read tool versions
import sys
from dataclasses import dataclass

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound

logger = logging.getLogger("preflight")
DEFAULT_MODELS = ("us.anthropic.claude-opus-5-5", "global.anthropic.claude-sonnet-5-5")
EDGE_REGION = "us-east-1"
_GEO_PREFIX = re.compile(r"^(us|eu|apac|jp|au|ca|global)\.")


@dataclass
class Result:
    name: str
    ok: bool
    fix: str


def node_version() -> str:
    try:
        # Resolved from PATH on purpose: the operator's node is what the CDK CLI will use,
        # and its version is only available from the binary itself (no Python API). Fixed
        # argv, no shell, no input.
        return subprocess.run(  # noqa: S603  # nosec B603 B607: fixed argv, literal program resolved from PATH on purpose, no shell, no untrusted input
            ["node", "--version"],  # noqa: S607
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def node_major(version: str) -> int | None:
    match = re.match(r"v?(\d+)\.", version)
    return int(match.group(1)) if match else None


def check_tools() -> list[Result]:
    results = [
        Result("uv", shutil.which("uv") is not None, "install uv: https://docs.astral.sh/uv/")
    ]
    major = node_major(node_version()) if shutil.which("node") else None
    results.append(
        Result(
            "node 22+",
            major is not None and major >= 22,
            "install Node.js 22 or newer (the CDK CLI runs through npx)",
        )
    )
    runtime = shutil.which("docker") or shutil.which("finch")
    results.append(
        Result(
            "finch or docker",
            runtime is not None,
            "install Docker or Finch; export CDK_DOCKER=docker (or finch)",
        )
    )
    return results


def check_bootstrap(session: boto3.Session, account: str, region: str) -> Result:
    name = f"CDK bootstrap in {region}"
    fix = f"npx aws-cdk@2.1143.0 bootstrap aws://{account}/{region}"
    try:
        session.client("cloudformation", region_name=region).describe_stacks(StackName="CDKToolkit")
        session.client("ssm", region_name=region).get_parameter(
            Name="/cdk-bootstrap/hnb659fds/version"
        )
    except ClientError:
        return Result(name, False, fix)
    return Result(name, True, "")


def base_model_id(profile_id: str) -> str:
    return _GEO_PREFIX.sub("", profile_id)


def check_model(bedrock, profile_id: str) -> Result:
    name = f"Bedrock model {profile_id}"
    fix = (
        "enable model access for this Anthropic model in the Amazon Bedrock console "
        "for this region, or pass a model id available here with "
        "-c orchestratorModel / -c specialistModel"
    )
    try:
        active = (
            bedrock.get_inference_profile(inferenceProfileIdentifier=profile_id).get("status")
            == "ACTIVE"
        )
        auth = bedrock.get_foundation_model_availability(modelId=base_model_id(profile_id))
        authorized = auth.get("authorizationStatus") == "AUTHORIZED"
    except ClientError:
        return Result(name, False, fix)
    return Result(name, active and authorized, fix)


def check_agentcore(session: boto3.Session, region: str) -> Result:
    name = f"AgentCore in {region}"
    try:
        session.client("bedrock-agentcore-control", region_name=region).list_agent_runtimes(
            maxResults=1
        )
    except (ClientError, BotoCoreError) as exc:
        return Result(
            name,
            False,
            f"AgentCore is not available or not permitted here ({type(exc).__name__}); "
            "pick a region where AgentCore Harness, Runtime, Gateway and Browser are offered",
        )
    return Result(name, True, "")


REGISTRY_REGIONS = ("us-west-2", "us-east-1")


def check_agent_registry(session: boto3.Session, region: str) -> Result:
    """AWS Agent Registry backs the MCP server catalog of -c agentRegistry=true."""
    name = f"Agent Registry in {region}"
    if region not in REGISTRY_REGIONS:
        # The stack still deploys; only the catalog is skipped (a synth-time warning).
        return Result(name, True, "")
    try:
        session.client("agent-registry-control", region_name=region).list_registries(maxResults=1)
    except (ClientError, BotoCoreError) as exc:
        return Result(
            name,
            False,
            f"Agent Registry is not reachable or not permitted here ({type(exc).__name__}); "
            "update boto3/awscli, allow agent-registry-control:ListRegistries, or deploy without "
            "-c agentRegistry=true",
        )
    return Result(name, True, "")


def exit_code(results: list[Result]) -> int:
    return 0 if all(r.ok for r in results) else 1


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--profile", default=None, help="AWS profile (defaults to the environment)")
    parser.add_argument("--region", required=True, help="region to deploy PhishTriageAgentic into")
    parser.add_argument("--orchestrator-model", default=DEFAULT_MODELS[0])
    parser.add_argument("--specialist-model", default=DEFAULT_MODELS[1])
    parser.add_argument(
        "--agent-registry",
        action="store_true",
        help="you will deploy with -c agentRegistry=true (adds an Agent Registry check)",
    )
    args = parser.parse_args(argv)
    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        identity = session.client("sts", region_name=args.region).get_caller_identity()
    except (NoCredentialsError, ProfileNotFound, ClientError, BotoCoreError) as exc:
        # Only the exception class name is logged, never its message or any session detail.
        logger.error(
            "no AWS identity for this profile and region (%s); sign in to the target account",
            type(exc).__name__,
        )
        return 2
    account = identity["Account"]
    logger.info("account %s, region %s", account, args.region)
    bedrock = session.client("bedrock", region_name=args.region)
    results = check_tools()
    results += [
        check_bootstrap(session, account, args.region),
        check_bootstrap(session, account, EDGE_REGION),
    ]
    results += [check_model(bedrock, m) for m in (args.orchestrator_model, args.specialist_model)]
    results.append(check_agentcore(session, args.region))
    if args.agent_registry:
        results.append(check_agent_registry(session, args.region))
    for r in results:
        logger.info("%s %s%s", "PASS" if r.ok else "FAIL", r.name, "" if r.ok else f"  -> {r.fix}")
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
