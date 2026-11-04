# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Resolve the owner key for a request (ported from v1).

API Gateway IAM auth gives the caller ARN. Every UI user shares the web proxy role, so
for that role only the verified Cognito sub in X-Console-User-Sub is appended, and a
proxy call without a valid sub is anonymous (403). The header is ignored for every
other caller, because only the proxy role's credentials can produce a valid SigV4
signature over it.
"""

import logging
import re

from phish_backend.common.config import settings

logger = logging.getLogger(__name__)

CONSOLE_USER_HEADER = "x-console-user-sub"
_SUB_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def normalize_caller_id(caller_arn: str) -> str:
    """Drop the volatile session name from an assumed-role ARN."""
    if not caller_arn:
        return ""
    if ":assumed-role/" in caller_arn:
        head, _, tail = caller_arn.partition(":assumed-role/")
        return f"{head}:assumed-role/{tail.split('/', 1)[0]}"
    return caller_arn


def _account_and_role(arn: str) -> tuple[str, str]:
    parts = arn.split(":")
    account = parts[4] if len(parts) >= 5 else ""
    role = ""
    if ":assumed-role/" in arn:
        role = arn.partition(":assumed-role/")[2].split("/", 1)[0]
    elif ":role/" in arn:
        role = arn.partition(":role/")[2].rsplit("/", 1)[-1]
    return account, role


def _is_proxy(caller_arn: str) -> bool:
    proxy = settings().proxy_role_arn
    if not proxy or not caller_arn:
        return False
    want = _account_and_role(proxy)
    return bool(want[1]) and want == _account_and_role(caller_arn)


def _console_sub(event: dict) -> str:
    for key, value in (event.get("headers") or {}).items():
        if isinstance(key, str) and key.lower() == CONSOLE_USER_HEADER:
            value = (value or "").strip()
            if _SUB_RE.match(value):
                return value
            logger.warning("ignoring malformed %s header", CONSOLE_USER_HEADER)
            return ""
    return ""


def _caller(event: dict) -> str:
    return ((event.get("requestContext") or {}).get("identity") or {}).get("userArn") or ""


def is_console(event: dict) -> bool:
    """True when the web console proxy role signed the request."""
    return _is_proxy(_caller(event))


def resolve_owner(event: dict) -> str:
    caller = _caller(event)
    normalized = normalize_caller_id(caller)
    if not normalized:
        return "anonymous"
    if _is_proxy(caller):
        sub = _console_sub(event)
        if sub:
            return f"{normalized}:{sub}"
        # Every UI user shares the proxy role; a role-only key would pool their data,
        # so the API answers 403 instead.
        logger.warning("proxy request without a valid user subject header; refused")
        return "anonymous"
    return normalized
