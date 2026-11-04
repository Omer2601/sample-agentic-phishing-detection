# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Cognito sign-up and sign-in.

signUpMode=app (default): admin-create-only pool; the web route POST /auth/register creates users.
signUpMode=cognito: native self sign-up with email verification. The invite code (app mode only)
and the email domain allowlist are opt-in.
"""

from __future__ import annotations

import json
from pathlib import Path

import aws_cdk as cdk
from aws_cdk import aws_cognito as cognito
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_secretsmanager as secretsmanager
from aws_cdk import aws_ssm as ssm
from constructs import Construct

from phish_infra.common import python_function, stack_output
from phish_infra.config import AppConfig

# Every name web/server/auth.py requests under the auth prefix (PARAM_NAMES,
# INVITE_PARAM_NAMES, SIGN_UP_PARAM_NAMES); infra/tests/test_auth.py compares the two.
WEB_READ_PARAM_NAMES = (
    "user_pool_id",
    "client_id",
    "cognito_domain",
    "public_base_url",
    "invite_secret_arn",
    "invite_allowed_email_domains",
    "sign_up_mode",
)

# v1 managed login style (managedLoginSettings in the v1 ui-auth construct), unchanged.
BRANDING = Path(__file__).with_name("managed_login_settings.json")
INVITE_SUBJECT = "Your phishing detection sign-in"
_INVITE_HEAD = (
    "Your phishing detection account is ready.\n\n"
    "Username: {username}\n"
    "Temporary password: {####}\n\n"
)
_INVITE_TAIL = " If you did not register, ignore this email."


def invite_body(mfa: str) -> str:
    if mfa == "required":
        step = (
            "Sign in with these details. You will choose a new password and set up an "
            "authenticator app on first sign-in."
        )
    else:
        step = (
            "Sign in with these details. You will choose a new password on first sign-in, and "
            "can add an authenticator app for a second factor."
        )
    return _INVITE_HEAD + step + _INVITE_TAIL


def _email(cfg: AppConfig) -> cognito.UserPoolEmail:
    """Cognito's own email by default. It sends at most 50 emails per day per account, enough
    for a demo; set -c sesFromAddress=<SES-verified address> for anything larger."""
    if cfg.ses_from_address:
        return cognito.UserPoolEmail.with_ses(from_email=cfg.ses_from_address)
    return cognito.UserPoolEmail.with_cognito()


class UserAuth(Construct):
    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        cfg: AppConfig,
        key: kms.IKey,
        public_base_url: str,
        backend_code: lambda_.Code,
    ) -> None:
        super().__init__(scope, id)
        name, env = cfg.app_name, cfg.environment
        self._app_mode = cfg.sign_up_mode == "app"
        self_signup = cfg.sign_up_mode == "cognito"
        plus = cfg.cognito_plan == "plus"

        triggers = None
        if self_signup and cfg.allowed_email_domains:
            # Native sign-up only: Cognito has no domain restriction, so a trigger enforces it.
            # In app mode POST /auth/register enforces the allowlist before AdminCreateUser.
            pre_sign_up = python_function(
                self,
                "PreSignUp",
                cfg=cfg,
                key=key,
                code=backend_code,
                handler="phish_backend.auth.pre_sign_up.handler",
                description="Rejects sign-ups whose email domain is not allowlisted",
                environment={"ALLOWED_EMAIL_DOMAINS": ",".join(cfg.allowed_email_domains)},
                timeout=cdk.Duration.seconds(5),
                memory_mb=128,
            )
            triggers = cognito.UserPoolTriggers(pre_sign_up=pre_sign_up)

        self.user_pool = cognito.UserPool(
            self,
            "UserPool",
            user_pool_name=f"{name}-users-{env}",
            self_sign_up_enabled=self_signup,
            user_verification=cognito.UserVerificationConfig(
                email_style=cognito.VerificationEmailStyle.CODE
            ),
            sign_in_aliases=cognito.SignInAliases(email=True),
            auto_verify=cognito.AutoVerifiedAttrs(email=True),
            standard_attributes=cognito.StandardAttributes(
                email=cognito.StandardAttribute(required=True, mutable=False)
            ),
            password_policy=cognito.PasswordPolicy(
                min_length=12,
                require_lowercase=True,
                require_uppercase=True,
                require_digits=True,
                require_symbols=True,
                temp_password_validity=cdk.Duration.days(3),
            ),
            # ESSENTIALS is the lowest plan with managed login; pinned so a CDK default change
            # cannot move the bill. -c cognitoPlan=plus buys threat protection (compromised
            # credentials, adaptive authentication), which has no free tier.
            feature_plan=cognito.FeaturePlan.PLUS if plus else cognito.FeaturePlan.ESSENTIALS,
            standard_threat_protection_mode=(
                cognito.StandardThreatProtectionMode.FULL_FUNCTION if plus else None
            ),
            # TOTP only (no SMS). Optional by default so a demo user is not forced through an
            # authenticator; -c mfa=required makes it the control that keeps a leaked password
            # (or invite code) from becoming an account.
            mfa=cognito.Mfa.REQUIRED if cfg.mfa == "required" else cognito.Mfa.OPTIONAL,
            mfa_second_factor=cognito.MfaSecondFactor(sms=False, otp=True),
            account_recovery=cognito.AccountRecovery.EMAIL_ONLY,
            # Sent by AdminCreateUser (POST /auth/register in app mode). Plain text on purpose.
            user_invitation=cognito.UserInvitationConfig(
                email_subject=INVITE_SUBJECT, email_body=invite_body(cfg.mfa)
            ),
            email=_email(cfg),
            lambda_triggers=triggers,
            deletion_protection=cfg.is_prod,
            removal_policy=cfg.removal_policy,
        )
        # Prefix from the stack UUID, not the account id, which would show in every login URL.
        stack_uuid = cdk.Fn.select(2, cdk.Fn.split("/", cdk.Stack.of(self).stack_id))
        domain = self.user_pool.add_domain(
            "ManagedLogin",
            cognito_domain=cognito.CognitoDomainOptions(
                domain_prefix=f"{name}-{env}-{cdk.Fn.select(0, cdk.Fn.split('-', stack_uuid))}"
            ),
            managed_login_version=cognito.ManagedLoginVersion.NEWER_MANAGED_LOGIN,
        )
        self.client = self.user_pool.add_client(
            "ConsoleClient",
            user_pool_client_name=f"{name}-console-{env}",
            # Confidential client: the secret stays in the web Lambda, so a browser cannot
            # exchange an authorization code on its own.
            generate_secret=True,
            auth_flows=cognito.AuthFlow(user_srp=True),
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(authorization_code_grant=True),
                scopes=[
                    cognito.OAuthScope.OPENID,
                    cognito.OAuthScope.EMAIL,
                    cognito.OAuthScope.PROFILE,
                ],
                callback_urls=[f"{public_base_url}/auth/callback"],
                logout_urls=[f"{public_base_url}/"],
            ),
            prevent_user_existence_errors=True,
            access_token_validity=cdk.Duration.hours(1),
            id_token_validity=cdk.Duration.hours(1),
            refresh_token_validity=cdk.Duration.days(1),
        )
        # L1: no L2 for managed login branding. Without it a CDK-created client renders
        # managed login unstyled.
        cognito.CfnManagedLoginBranding(
            self,
            "Branding",
            user_pool_id=self.user_pool.user_pool_id,
            client_id=self.client.user_pool_client_id,
            use_cognito_provided_values=False,
            return_merged_resources=False,
            settings=json.loads(BRANDING.read_text(encoding="utf-8")),
        )

        self.invite_secret: secretsmanager.Secret | None = None
        if cfg.invite_code:
            self.invite_secret = secretsmanager.Secret(
                self,
                "InviteCode",
                description=f"Invite code for {name} {env}: checked by POST /auth/register",
                encryption_key=key,
                generate_secret_string=secretsmanager.SecretStringGenerator(
                    # The empty JSON object the generated "code" key is added to. It holds
                    # no secret; the value is generated by Secrets Manager at deploy time.
                    secret_string_template=json.dumps({}),
                    generate_string_key="code",
                    password_length=32,
                    exclude_punctuation=True,
                    exclude_characters=" ",
                ),
                removal_policy=cfg.removal_policy,
            )

        self.ssm_prefix = f"/{name}/{env}/auth"
        values = {
            "user_pool_id": self.user_pool.user_pool_id,
            "client_id": self.client.user_pool_client_id,
            "cognito_domain": domain.base_url(),
            "public_base_url": public_base_url,
            "sign_up_mode": cfg.sign_up_mode,
            "invite_enabled": str(cfg.invite_code).lower(),
            # v1 parameter name, kept because the web tier reads it.
            "invite_allowed_email_domains": ",".join(cfg.allowed_email_domains) or "*",
        }
        if self.invite_secret is not None:
            values["invite_secret_arn"] = self.invite_secret.secret_arn
        # Granted whether or not they exist: the web tier requests all of them in one
        # GetParameters call, and one ungranted name denies the whole call.
        self._param_names = list(dict.fromkeys([*values, *WEB_READ_PARAM_NAMES]))
        for key_name, value in values.items():
            ssm.StringParameter(
                self,
                f"Param-{key_name}",
                parameter_name=f"{self.ssm_prefix}/{key_name}",
                string_value=value,
                description=f"UI authentication: {key_name}",
            )

        stack_output(self, "UserPoolId", self.user_pool.user_pool_id, "Console user pool")
        stack_output(self, "ManagedLoginUrl", domain.base_url(), "Cognito managed login base URL")
        if self.invite_secret is not None:
            stack_output(
                self,
                "InviteCodeSecretArn",
                self.invite_secret.secret_arn,
                "Secret holding the invite code; share the code, never paste it into chat",
            )

    def grant_read(self, role: iam.IRole) -> None:
        stack = cdk.Stack.of(self)
        role.add_to_principal_policy(
            iam.PolicyStatement(
                actions=["ssm:GetParameters", "ssm:GetParameter"],
                resources=[
                    stack.format_arn(
                        service="ssm",
                        resource="parameter",
                        resource_name=f"{self.ssm_prefix.lstrip('/')}/{n}",
                    )
                    for n in self._param_names
                ],
            )
        )
        role.add_to_principal_policy(
            iam.PolicyStatement(
                actions=["cognito-idp:DescribeUserPoolClient"],
                resources=[self.user_pool.user_pool_arn],
            )
        )

    def grant_register(self, role: iam.IRole) -> None:
        """Rights for POST /auth/register. Nothing in cognito mode: users register with Cognito
        directly."""
        if not self._app_mode:
            return
        role.add_to_principal_policy(
            iam.PolicyStatement(
                # AdminCreateUser only: Cognito emails a temporary password, which proves the
                # registrant owns the inbox. The web tier never sets a password itself.
                actions=["cognito-idp:AdminCreateUser"],
                resources=[self.user_pool.user_pool_arn],
            )
        )
        if self.invite_secret is not None:
            self.invite_secret.grant_read(role)
