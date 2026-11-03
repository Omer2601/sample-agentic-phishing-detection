# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Cognito PreSignUp trigger: enforce the email domain allowlist for native self sign-up."""

import logging
import os

logger = logging.getLogger(__name__)
MESSAGE = "Sign-up is limited to approved email domains."


class SignUpRefused(Exception):
    """Cognito shows the message of any exception raised by the trigger to the user."""


def _domains() -> set[str]:
    raw = os.environ.get("ALLOWED_EMAIL_DOMAINS", "")
    return {d.strip().lower() for d in raw.split(",") if d.strip()}


def handler(event, context):
    # Admin-created users pass: the app-mode register route enforces the allowlist itself.
    if event.get("triggerSource") != "PreSignUp_SignUp":
        return event
    attributes = (event.get("request") or {}).get("userAttributes") or {}
    email = str(attributes.get("email", "")).strip().lower()
    local, _, domain = email.rpartition("@")
    allowed = _domains()
    if not local or not domain or (allowed and domain not in allowed):
        logger.info("sign-up refused for a non-allowlisted domain")
        raise SignUpRefused(MESSAGE)
    return event
