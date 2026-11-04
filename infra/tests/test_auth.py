# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import aws_cdk as cdk
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk.assertions import Match, Template

from phish_infra.config import load_config
from phish_infra.constructs.auth import UserAuth
from phish_infra.constructs.data import DataLayer

PRE_SIGN_UP = "phish_backend.auth.pre_sign_up.handler"


def synth(app_context, test_env, tmp_path, **extra):
    app = cdk.App(context={**app_context, **extra})
    stack = cdk.Stack(app, "S", env=test_env)
    cfg = load_config(app.node)
    data = DataLayer(stack, "Data", cfg=cfg)
    auth = UserAuth(
        stack,
        "Auth",
        cfg=cfg,
        key=data.key,
        public_base_url="https://d111.cloudfront.net",
        backend_code=lambda_.Code.from_asset(str(tmp_path)),
    )
    role = iam.Role(stack, "WebRole", assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
    auth.grant_read(role)
    auth.grant_register(role)
    return Template.from_stack(stack)


def params(t):
    return {
        p["Properties"]["Name"]: p["Properties"]["Value"]
        for p in t.find_resources("AWS::SSM::Parameter").values()
    }


def pre_sign_up_functions(t):
    return t.find_resources("AWS::Lambda::Function", {"Properties": {"Handler": PRE_SIGN_UP}})


def web_role_policy(t):
    return str(
        [
            p
            for p in t.find_resources("AWS::IAM::Policy").values()
            if "WebRole" in str(p["Properties"]["Roles"])
        ]
    )


def test_default_is_app_route_sign_up_with_mfa(app_context, test_env, tmp_path):
    # signUpMode=app: the pool stays admin-create-only (Amazon accounts force this back on anyway);
    # the web route POST /auth/register creates users with AdminCreateUser.
    t = synth(app_context, test_env, tmp_path)
    t.has_resource_properties(
        "AWS::Cognito::UserPool",
        {
            "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
            # Decision 2026-09-29: TOTP offered, not forced (-c mfa=required forces it).
            "MfaConfiguration": "OPTIONAL",
            "EnabledMfas": ["SOFTWARE_TOKEN_MFA"],
            "AutoVerifiedAttributes": ["email"],
            "Policies": {
                "PasswordPolicy": Match.object_like({"MinimumLength": 12, "RequireSymbols": True})
            },
        },
    )
    t.resource_count_is("AWS::SecretsManager::Secret", 0)
    assert not pre_sign_up_functions(t)
    p = params(t)
    assert p["/phish/dev/auth/sign_up_mode"] == "app"
    assert p["/phish/dev/auth/invite_enabled"] == "false"
    assert p["/phish/dev/auth/invite_allowed_email_domains"] == "*"
    assert "/phish/dev/auth/invite_secret_arn" not in p
    policy = web_role_policy(t)
    assert "cognito-idp:AdminCreateUser" in policy
    # Cognito emails a temporary password (proves inbox ownership); the web tier never sets one.
    assert "AdminSetUserPassword" not in policy
    assert "secretsmanager:GetSecretValue" not in policy


def test_invite_mode_adds_secret(app_context, test_env, tmp_path):
    t = synth(app_context, test_env, tmp_path, inviteCode=True)
    t.has_resource_properties(
        "AWS::Cognito::UserPool", {"AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True}}
    )
    t.resource_count_is("AWS::SecretsManager::Secret", 1)
    t.has_resource_properties("AWS::SecretsManager::Secret", {"KmsKeyId": Match.any_value()})
    assert params(t)["/phish/dev/auth/invite_enabled"] == "true"
    assert "/phish/dev/auth/invite_secret_arn" in params(t)
    assert "InviteCodeSecretArn" in t.find_outputs("*")
    assert "secretsmanager:GetSecretValue" in web_role_policy(t)


def test_app_mode_allowlist_is_enforced_by_the_web_route_not_a_trigger(
    app_context, test_env, tmp_path
):
    t = synth(app_context, test_env, tmp_path, allowedEmailDomains="example.com")
    assert not pre_sign_up_functions(t)
    assert params(t)["/phish/dev/auth/invite_allowed_email_domains"] == "example.com"


def test_cognito_mode_is_native_self_sign_up(app_context, test_env, tmp_path):
    t = synth(app_context, test_env, tmp_path, signUpMode="cognito")
    t.has_resource_properties(
        "AWS::Cognito::UserPool", {"AdminCreateUserConfig": {"AllowAdminCreateUserOnly": False}}
    )
    assert not pre_sign_up_functions(t)
    assert params(t)["/phish/dev/auth/sign_up_mode"] == "cognito"
    assert "cognito-idp:AdminCreateUser" not in web_role_policy(t)


def test_cognito_mode_domain_allowlist_adds_pre_sign_up_trigger(app_context, test_env, tmp_path):
    t = synth(
        app_context, test_env, tmp_path, signUpMode="cognito", allowedEmailDomains="example.com"
    )
    t.has_resource_properties(
        "AWS::Lambda::Function",
        {
            "Handler": PRE_SIGN_UP,
            "Environment": {
                "Variables": Match.object_like({"ALLOWED_EMAIL_DOMAINS": "example.com"})
            },
        },
    )
    t.has_resource_properties(
        "AWS::Cognito::UserPool", {"LambdaConfig": {"PreSignUp": Match.any_value()}}
    )


def test_client_uses_code_flow_with_callback(app_context, test_env, tmp_path):
    synth(app_context, test_env, tmp_path).has_resource_properties(
        "AWS::Cognito::UserPoolClient",
        {
            "AllowedOAuthFlows": ["code"],
            "GenerateSecret": True,
            "CallbackURLs": ["https://d111.cloudfront.net/auth/callback"],
            "PreventUserExistenceErrors": "ENABLED",
        },
    )


def test_client_registers_the_sign_out_return_url(app_context, test_env, tmp_path):
    # GET /auth/logout sends logout_uri=<public base>/ to Cognito's /logout, which
    # refuses any value not listed here byte for byte (see web/server/auth.py).
    synth(app_context, test_env, tmp_path).has_resource_properties(
        "AWS::Cognito::UserPoolClient",
        {"LogoutURLs": ["https://d111.cloudfront.net/"]},
    )


def test_branding_is_applied(app_context, test_env, tmp_path):
    synth(app_context, test_env, tmp_path).has_resource_properties(
        "AWS::Cognito::ManagedLoginBranding",
        {"Settings": Match.object_like({"components": Match.any_value()})},
    )


def test_auth_outputs_have_exact_keys(app_context, test_env, tmp_path):
    assert {"UserPoolId", "ManagedLoginUrl"} <= set(
        synth(app_context, test_env, tmp_path).find_outputs("*")
    )


def test_invitation_email_carries_username_and_temporary_password(app_context, test_env, tmp_path):
    (pool,) = (
        synth(app_context, test_env, tmp_path).find_resources("AWS::Cognito::UserPool").values()
    )
    template = pool["Properties"]["AdminCreateUserConfig"]["InviteMessageTemplate"]
    assert template["EmailSubject"] == "Your phishing detection sign-in"
    body = template["EmailMessage"]
    assert "{username}" in body and "{####}" in body
    assert "<" not in body  # plain text
    assert "\u2014" not in body and "\u2013" not in body


def test_default_email_is_cognito(app_context, test_env, tmp_path):
    (pool,) = (
        synth(app_context, test_env, tmp_path).find_resources("AWS::Cognito::UserPool").values()
    )
    config = pool["Properties"].get("EmailConfiguration", {})
    assert config.get("EmailSendingAccount", "COGNITO_DEFAULT") == "COGNITO_DEFAULT"


def test_ses_from_address_switches_to_ses(app_context, test_env, tmp_path):
    t = synth(app_context, test_env, tmp_path, sesFromAddress="alerts@example.com")
    t.has_resource_properties(
        "AWS::Cognito::UserPool",
        {
            "EmailConfiguration": Match.object_like(
                {"EmailSendingAccount": "DEVELOPER", "From": "alerts@example.com"}
            )
        },
    )


def test_mfa_required_flag_forces_totp(app_context, test_env, tmp_path):
    t = synth(app_context, test_env, tmp_path, mfa="required")
    t.has_resource_properties(
        "AWS::Cognito::UserPool",
        {"MfaConfiguration": "ON", "EnabledMfas": ["SOFTWARE_TOKEN_MFA"]},
    )


def test_invitation_email_matches_the_mfa_mode(app_context, test_env, tmp_path):
    def body(t):
        pool = next(iter(t.find_resources("AWS::Cognito::UserPool").values()))
        return pool["Properties"]["AdminCreateUserConfig"]["InviteMessageTemplate"]["EmailMessage"]

    optional = body(synth(app_context, test_env, tmp_path))
    required = body(synth(app_context, test_env, tmp_path, mfa="required"))
    for text in (optional, required):
        assert "{username}" in text and "{####}" in text
    assert "will choose a new password and set up an authenticator" in required
    assert "set up an authenticator" not in optional


def test_default_plan_is_essentials_without_threat_protection(app_context, test_env, tmp_path):
    t = synth(app_context, test_env, tmp_path)
    t.has_resource_properties(
        "AWS::Cognito::UserPool",
        {"UserPoolTier": "ESSENTIALS", "UserPoolAddOns": Match.absent()},
    )


def test_plus_plan_enforces_threat_protection(app_context, test_env, tmp_path):
    t = synth(app_context, test_env, tmp_path, cognitoPlan="plus")
    t.has_resource_properties(
        "AWS::Cognito::UserPool",
        {"UserPoolTier": "PLUS", "UserPoolAddOns": {"AdvancedSecurityMode": "ENFORCED"}},
    )


def _web_requested_names():
    # The web tier asks for these names in one GetParameters call (web/server/auth.py).
    import ast

    from phish_infra.common import REPO_ROOT

    tree = ast.parse((REPO_ROOT / "web" / "server" / "auth.py").read_text())
    names = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name)
            and t.id in ("PARAM_NAMES", "INVITE_PARAM_NAMES", "SIGN_UP_PARAM_NAMES")
            for t in node.targets
        ):
            names += list(ast.literal_eval(node.value))
    assert len(names) >= 7, names
    return names


def test_web_role_may_read_every_parameter_the_web_tier_requests(app_context, test_env, tmp_path):
    # UI e2e (2026-09-29): with inviteCode=false invite_secret_arn is not created, it was not
    # granted, and GetParameters with one ungranted name denies the whole call (web 503).
    for extra in ({}, {"inviteCode": True}):
        policy = web_role_policy(synth(app_context, test_env, tmp_path, **extra))
        for name in _web_requested_names():
            assert f"/auth/{name}" in policy, (extra, name)


def test_infra_param_list_matches_the_web_tier():
    from phish_infra.constructs.auth import WEB_READ_PARAM_NAMES

    assert sorted(WEB_READ_PARAM_NAMES) == sorted(_web_requested_names())
