# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Cognito OIDC authentication for the UI tier.

WHY THIS LIVES IN THE SERVING TIER
----------------------------------
This module runs on Lambda behind a CloudFront distribution, where the AWS Lambda
Web Adapter runs the gunicorn app. There is no load balancer to offload the
Cognito flow to, and Lambda@Edge would have to be deployed in us-east-1 while this
stack is regional, and it cannot hold a server-side session. Running the
authorization code flow in the tier that already signs API requests keeps the
credential handling in one place.

WHY CONFIGURATION IS READ AT RUNTIME
------------------------------------
The redirect URI must be the CloudFront domain, so the Cognito app client cannot
be created until the distribution exists, and the distribution depends on the
Lambda function's URL. Passing the client id to the function as an environment
variable would therefore close a dependency cycle in CloudFormation. Reading it
from SSM at startup means the function environment depends only on a path
string, which breaks the cycle.

PERSONAL DATA
-------------
Registration and sign-in process each user's email address, which is personal data.
It is stored only in the Cognito user pool (AdminCreateUser); logs carry the email
domain, never the full address. Whoever deploys this sample is responsible for the
privacy obligations that apply to their users and jurisdiction (for example GDPR),
under the AWS shared responsibility model: https://aws.amazon.com/compliance/shared-responsibility-model/
and https://aws.amazon.com/compliance/data-privacy/ (see also docs/threat-model.md).

FAIL CLOSED
-----------
If configuration cannot be loaded the application serves 503 rather than serving
unauthenticated content. A missing parameter is an outage, not an open door.

REGISTRATION IS AN APPLICATION ROUTE, NOT A COGNITO FEATURE
-----------------------------------------------------------
The user pool is admin-create-only (AllowAdminCreateUserOnly=true) in every
deployment, because that flag is read directly by internal detection and an
auto-mitigation exists that turns it back on unattended: a deployment relying on
Cognito self-registration breaks without warning rather than raising a ticket.
Self-service registration is therefore delivered here instead, by register_user
below, which checks a shared invite code when one is configured and calls
AdminCreateUser with DesiredDeliveryMediums EMAIL and no password. Cognito
generates a temporary password and emails it using the pool's invitation
template, so the first sign-in proves the caller owns the inbox, and managed
login then forces the user to choose their own password. Each registration sends
one email, which counts against the Cognito default email quota (50 per day per
account) unless the pool is configured to send through Amazon SES.

The invite code is optional. It is required only when the operator deploys with
-c inviteCode=true, which creates the Secrets Manager secret and writes its ARN to
the invite_secret_arn SSM parameter; with no parameter, anyone who can reach the
page can register. The optional domain allowlist (invite_allowed_email_domains)
works the same either way.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import urllib.parse
import urllib.request

import boto3
import jwt
from jwt import PyJWKClient

log = logging.getLogger("auth")

# Path prefix for SSM parameters: a deterministic string supplied by CDK rather
# than a reference to a construct, which is what avoids a dependency cycle.
AUTH_SSM_PREFIX = os.environ.get("AUTH_SSM_PREFIX", "").rstrip("/")

PARAM_NAMES = ("user_pool_id", "client_id", "cognito_domain", "public_base_url")

# Read from the same SSM path but not required: a deployment without them simply
# has no invite route, and the console still serves. Treating them as mandatory
# would turn "invite not configured" into a total outage.
INVITE_PARAM_NAMES = ("invite_secret_arn", "invite_allowed_email_domains")

# Optional too: "app" (POST /auth/register creates users) or "cognito" (native
# Cognito self sign-up). A missing parameter means "app", the v1 behaviour.
SIGN_UP_PARAM_NAMES = ("sign_up_mode",)

# JSON key inside the invite secret. Must match the key infra generates the value
# under (the auth construct in infra/phish_infra, -c inviteCode=true).
INVITE_CODE_JSON_KEY = "code"

# Sentinel published by CDK when no email domain restriction is configured.
INVITE_ANY_DOMAIN = "*"

# Label separating this key's purpose from any other use of the client secret, so
# the state cookie key cannot be interchanged with the secret itself.
COOKIE_KEY_INFO = b"state-cookie-v2"

# Session lifetime. Cognito ID tokens expire in one hour by default; the cookie is
# capped to the same window so a stolen cookie cannot outlive the token inside it.
SESSION_MAX_AGE = int(os.environ.get("SESSION_MAX_AGE", "3600"))

# The __Host- prefix instructs the browser to reject the cookie unless it is
# Secure, has Path=/ and carries no Domain attribute, which prevents a
# subdomain from setting or overwriting it.
SESSION_COOKIE = "__Host-pg_session"
STATE_COOKIE = "__Host-pg_state"

_lock = threading.Lock()
_config: dict | None = None
_jwk_client: PyJWKClient | None = None


class AuthConfigError(RuntimeError):
    """Raised when authentication configuration cannot be loaded."""


def _require_https(url: str) -> str:
    """Reject anything that is not https before it reaches urlopen.

    urlopen honours file: and custom schemes, so a token endpoint assembled from
    a configuration value could otherwise read from the local filesystem.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"refusing non-https scheme: {parsed.scheme or '(none)'}")
    if not parsed.netloc:
        raise ValueError("refusing URL without a host")
    return url


def config() -> dict:
    """Load and cache authentication configuration.

    Raises AuthConfigError so callers can fail closed rather than continuing
    with authentication silently disabled.
    """
    global _config, _jwk_client
    with _lock:
        if _config is not None:
            return _config

        if not AUTH_SSM_PREFIX:
            raise AuthConfigError(
                "AUTH_SSM_PREFIX must be set; refusing to serve without authentication"
            )

        region = os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION")
        # Named explicitly rather than fetched by path: GetParametersByPath needs a
        # wildcard in the IAM policy, and every name here can be granted exactly.
        # The invite names ride along in the same call, so they cost no extra
        # latency; GetParameters reports names it could not find in
        # InvalidParameters rather than failing the call, which is what makes the
        # optional ones safe to request.
        try:
            ssm = boto3.client("ssm", region_name=region)
            got = ssm.get_parameters(
                Names=[
                    f"{AUTH_SSM_PREFIX}/{n}"
                    for n in PARAM_NAMES + INVITE_PARAM_NAMES + SIGN_UP_PARAM_NAMES
                ]
            )
            params = {p["Name"].rsplit("/", 1)[-1]: p["Value"] for p in got["Parameters"]}
        except Exception as exc:  # noqa: BLE001 - surfaced as a 503 by the caller
            raise AuthConfigError(f"could not load auth configuration: {exc}") from exc

        missing = [k for k in PARAM_NAMES if not params.get(k)]
        if missing:
            raise AuthConfigError(f"missing SSM parameters: {', '.join(missing)}")

        # The client secret is read from Cognito, which generated it, rather than
        # copied into another store. Copying it would mean either a custom
        # resource or a template parameter, and both risk the value appearing in
        # CloudFormation where cloudformation:GetTemplate would expose it.
        try:
            idp = boto3.client("cognito-idp", region_name=region)
            described = idp.describe_user_pool_client(
                UserPoolId=params["user_pool_id"], ClientId=params["client_id"]
            )
            client_secret = described["UserPoolClient"].get("ClientSecret")
        except Exception as exc:  # noqa: BLE001
            raise AuthConfigError(f"could not read client secret: {exc}") from exc
        if not client_secret:
            raise AuthConfigError("user pool client has no secret")

        # The state cookie key is derived from the client secret rather than
        # stored separately. A stored key would be one more secret to hold and
        # rotate, and the derivation is domain separated so the two values are
        # not interchangeable.
        cookie_key = hmac.new(client_secret.encode(), COOKIE_KEY_INFO, hashlib.sha256).digest()

        issuer = f"https://cognito-idp.{region}.amazonaws.com/{params['user_pool_id']}"
        _config = {
            "user_pool_id": params["user_pool_id"],
            "client_id": params["client_id"],
            "client_secret": client_secret,
            "cookie_key": cookie_key,
            "domain": params["cognito_domain"].rstrip("/"),
            "base_url": params["public_base_url"].rstrip("/"),
            "issuer": issuer,
            "jwks_uri": f"{issuer}/.well-known/jwks.json",
            "region": region,
            # The ARN of the secret holding the invite code, never the code. The
            # value is fetched on the first redemption (see _invite_code) so a
            # deployment with no invite route never calls Secrets Manager.
            "invite_secret_arn": params.get("invite_secret_arn", ""),
            "invite_allowed_email_domains": params.get(
                "invite_allowed_email_domains", INVITE_ANY_DOMAIN
            ),
            "sign_up_mode": params.get("sign_up_mode", "app"),
        }
        # PyJWKClient caches signing keys, so the JWKS endpoint is not called on
        # every request. A per-request fetch would add latency and could rate
        # limit the pool under load.
        _jwk_client = PyJWKClient(_config["jwks_uri"], cache_keys=True)
        log.info("auth configured for pool %s", params["user_pool_id"])
        return _config


# --------------------------------------------------------------------------- #
# Cookie helpers
# --------------------------------------------------------------------------- #


def _sign(value: str, key: bytes) -> str:
    mac = hmac.new(key, value.encode(), hashlib.sha256).digest()
    return f"{value}.{base64.urlsafe_b64encode(mac).decode().rstrip('=')}"


def _unsign(signed: str, key: bytes) -> str | None:
    """Return the payload if the signature is valid, else None."""
    if "." not in signed:
        return None
    value, _, provided = signed.rpartition(".")
    expected = (
        base64.urlsafe_b64encode(hmac.new(key, value.encode(), hashlib.sha256).digest())
        .decode()
        .rstrip("=")
    )
    # compare_digest to avoid leaking the position of the first differing byte.
    return value if hmac.compare_digest(provided, expected) else None


def read_cookies(environ: dict) -> dict[str, str]:
    raw = environ.get("HTTP_COOKIE", "")
    out: dict[str, str] = {}
    for part in raw.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip()] = v.strip()
    return out


def _set_cookie(name: str, value: str, max_age: int) -> tuple[str, str]:
    return (
        "Set-Cookie",
        f"{name}={value}; Max-Age={max_age}; Path=/; Secure; HttpOnly; SameSite=Lax",
    )


def _clear_cookie(name: str) -> tuple[str, str]:
    return ("Set-Cookie", f"{name}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax")


# --------------------------------------------------------------------------- #
# Session verification
# --------------------------------------------------------------------------- #


def current_user(environ: dict) -> dict | None:
    """Return verified ID token claims, or None when not authenticated.

    The cookie carries the Cognito ID token, whose signature, issuer, audience
    and expiry are all verified here. Nothing about the caller is trusted: a
    forged or expired token fails verification and is treated as anonymous.
    """
    cfg = config()
    token = read_cookies(environ).get(SESSION_COOKIE)
    if not token:
        return None
    try:
        signing_key = _jwk_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=cfg["client_id"],
            issuer=cfg["issuer"],
            options={"require": ["exp", "iat", "aud", "iss"]},
        )
    except Exception as exc:  # noqa: BLE001 - any failure means unauthenticated
        log.info("session rejected: %s", type(exc).__name__)
        return None
    # An access token also validates against the same key and issuer, so the
    # intended use is checked explicitly.
    if claims.get("token_use") != "id":
        # The logged value is the token_use claim ("id" or "access"), a type
        # discriminator. No credential material is logged.
        log.info("session rejected: wrong claim use %s", claims.get("token_use"))
        return None
    return claims


# --------------------------------------------------------------------------- #
# Authorization code flow
# --------------------------------------------------------------------------- #


def _safe_target(raw: str | None) -> str:
    """Confine a post-login redirect to this origin.

    A value taken from the query string could be an absolute URL or a
    protocol-relative "//evil.example" path, either of which would turn the login
    endpoint into an open redirect that lends this origin's credibility to an
    attacker's page. Only a single-slash local path is accepted.
    """
    if not raw or not raw.startswith("/") or raw.startswith("//"):
        return "/"
    # A backslash is normalised to a forward slash by some browsers, so "/\evil"
    # would escape the origin.
    if "\\" in raw or "://" in raw:
        return "/"
    return raw


def login_redirect(environ: dict) -> tuple[str, list[tuple[str, str]]]:
    """Begin the flow: redirect to the Hosted UI with state and PKCE."""
    return _authorize_redirect(environ, "/oauth2/authorize")


def signup_redirect(environ: dict) -> tuple[str, list[tuple[str, str]]]:
    """Send the browser to Cognito managed sign-up (sign_up_mode "cognito").

    Same parameters, state cookie and PKCE as login: after sign-up Cognito returns
    to /auth/callback with a code, and the callback accepts only a code that
    round-trips the signed state cookie.
    """
    return _authorize_redirect(environ, "/signup")


def _authorize_redirect(environ: dict, endpoint: str) -> tuple[str, list[tuple[str, str]]]:
    cfg = config()
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    # Two distinct random values with different jobs. "state" defends the redirect
    # itself against CSRF by round-tripping through the query string. "nonce" is an
    # OIDC replay defence: it is sent to the authorize endpoint, Cognito embeds it
    # in the id_token, and the callback checks the token carries the value we chose.
    # Without it, an id_token minted for a different authorize request could be
    # replayed into this exchange.
    state_token = secrets.token_urlsafe(16)
    oidc_nonce = secrets.token_urlsafe(32)

    # The path the user asked for is carried through the flow so login returns
    # them where they started rather than always to the root. Both sources are
    # caller controlled, so both go through the same validation.
    query = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
    target = _safe_target((query.get("next") or [None])[0] or environ.get("HTTP_X_ORIGINAL_PATH"))

    state_payload = (
        base64.urlsafe_b64encode(
            json.dumps({"n": state_token, "v": verifier, "t": target, "no": oidc_nonce}).encode()
        )
        .decode()
        .rstrip("=")
    )

    params = {
        "client_id": cfg["client_id"],
        "response_type": "code",
        "scope": "openid email profile",
        "redirect_uri": f"{cfg['base_url']}/auth/callback",
        "state": state_token,
        "nonce": oidc_nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    url = f"{cfg['domain']}{endpoint}?{urllib.parse.urlencode(params)}"
    # The state cookie is short lived because it is only needed for the round
    # trip to the Hosted UI.
    return url, [_set_cookie(STATE_COOKIE, _sign(state_payload, cfg["cookie_key"]), 600)]


def handle_callback(environ: dict) -> tuple[str, list[tuple[str, str]]] | None:
    """Complete the flow. Returns (redirect_target, headers) or None on failure."""
    cfg = config()
    query = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
    code = (query.get("code") or [""])[0]
    returned_state = (query.get("state") or [""])[0]
    if not code or not returned_state:
        return None

    signed = read_cookies(environ).get(STATE_COOKIE, "")
    payload = _unsign(signed, cfg["cookie_key"]) if signed else None
    if not payload:
        log.warning("callback rejected: missing or invalid state cookie")
        return None
    try:
        state = json.loads(base64.urlsafe_b64decode(payload + "=="))
    except Exception:  # noqa: BLE001
        log.warning("callback rejected: unparsable state")
        return None

    # Comparing the state in the cookie against the one Cognito returned is what
    # stops an attacker replaying their own authorization code into this
    # browser's session.
    if not hmac.compare_digest(str(state.get("n", "")), returned_state):
        log.warning("callback rejected: state mismatch")
        return None

    body = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "client_id": cfg["client_id"],
            "code": code,
            "redirect_uri": f"{cfg['base_url']}/auth/callback",
            "code_verifier": state.get("v", ""),
        }
    ).encode()
    basic = base64.b64encode(f"{cfg['client_id']}:{cfg['client_secret']}".encode()).decode()
    req = urllib.request.Request(  # noqa: S310 (scheme checked by _require_https)
        _require_https(f"{cfg['domain']}/oauth2/token"),
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {basic}",
        },
    )
    try:
        # urlopen accepts file: and custom schemes; the URL was validated by
        # _require_https, so only https with a host reaches this call.
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310  # nosec B310
            tokens = json.loads(resp.read().decode())
    except Exception as exc:  # noqa: BLE001
        # Only the exception class name is logged (for example HTTPError), never
        # the request body, response body, or any credential material.
        log.warning("code exchange failed: %s", type(exc).__name__)
        return None

    id_token = tokens.get("id_token")
    if not id_token:
        return None

    # The token is verified before it is handed a cookie, so a malformed or
    # unexpected response cannot create a session.
    probe = dict(environ)
    probe["HTTP_COOKIE"] = f"{SESSION_COOKIE}={id_token}"
    claims = current_user(probe)
    if claims is None:
        log.warning("token exchange returned a token that failed verification")
        return None

    # Bind the id_token to this login attempt: the nonce we sent to authorize must
    # be the nonce Cognito embedded in the token. A token obtained for any other
    # authorize request (a replay) will not carry our nonce and is rejected.
    if not hmac.compare_digest(str(claims.get("nonce", "")), str(state.get("no", ""))):
        log.warning("callback rejected: id_token nonce mismatch")
        return None

    target = _safe_target(state.get("t"))
    headers = [
        _set_cookie(SESSION_COOKIE, id_token, min(SESSION_MAX_AGE, 3600)),
        _clear_cookie(STATE_COOKIE),
    ]
    return target, headers


def logout_redirect() -> tuple[str, list[tuple[str, str]]]:
    """Clear the local session and end the Cognito session too.

    Clearing only the cookie would leave the Hosted UI session intact, so the
    next visit would sign straight back in without prompting, which is not what
    a user pressing sign out expects.
    """
    cfg = config()
    params = urllib.parse.urlencode(
        {"client_id": cfg["client_id"], "logout_uri": f"{cfg['base_url']}/"}
    )
    return (
        f"{cfg['domain']}/logout?{params}",
        [_clear_cookie(SESSION_COOKIE), _clear_cookie(STATE_COOKIE)],
    )


# --------------------------------------------------------------------------- #
# Invite-gated registration
# --------------------------------------------------------------------------- #

# Outcomes returned by register_user. Symbolic rather than HTTP status codes so
# this module stays free of HTTP concerns; wsgi.py owns the mapping.
REGISTER_OK = "created"
REGISTER_BAD_REQUEST = "invalid_request"
REGISTER_BAD_CODE = "invalid_invite"
REGISTER_EMAIL_NOT_ALLOWED = "email_not_allowed"
REGISTER_UNAVAILABLE = "unavailable"
# Raised by the HTTP layer rather than by register_user, but it lives with the
# others so the set of values the client can receive is defined in one place.
REGISTER_RATE_LIMITED = "rate_limited"

# The one message a successful registration returns. It is also the message an
# already-registered address receives, word for word, so the response cannot be
# used to learn whether an address has an account.
REGISTER_OK_MESSAGE = "We emailed you a temporary password. Sign in with it, then choose your own."

# Cognito's own limit, enforced here so an oversized field is a clean 400 rather
# than a ValidationException from the SDK: Username is capped at 128 characters.
INVITE_MAX_EMAIL_LEN = 128
# The generated code is 32 characters. The cap only exists to stop an absurd
# submission being hashed; it is not a correctness check.
INVITE_MAX_CODE_LEN = 256
# Cap on any service message forwarded to the caller. Matches the cap the SPA
# applies when it renders one, so both halves truncate at the same point and the
# rendered text is exactly what this tier sent.
INVITE_MAX_MESSAGE_LEN = 200

# Deliberately loose. Cognito is the authority on whether an address is usable,
# and a strict pattern here would reject valid addresses while adding nothing:
# the invite code, not the shape of the address, is the gate.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+(?:\.[^@\s.]+)+$")

_register_lock = threading.Lock()
_invite_code_cache: str | None = None


class InviteNotConfigured(RuntimeError):
    """Raised when this deployment has no invite secret wired up."""


def _code_fingerprint(value: str) -> str:
    """A short, non-reversible tag for a submitted invite code, safe to log.

    The submitted value itself must never be logged: for a wrong guess that is
    noise, and for a right guess it is the credential in plaintext in CloudWatch.
    A SHA-256 prefix is enough to correlate repeated attempts in a log while
    being far too short to serve as a verifier for the real code.
    """
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def _invite_code(cfg: dict) -> str:
    """Fetch and cache the invite code from Secrets Manager.

    Resolved at runtime rather than injected. A CloudFormation dynamic reference
    would materialise the value into the function configuration, where anyone
    with lambda:GetFunctionConfiguration could read it; baking it into the
    package would put it in a published artefact. The web role holds
    secretsmanager:GetSecretValue on this one secret ARN and nothing else
    (granted by infra only when -c inviteCode=true).
    """
    global _invite_code_cache
    with _register_lock:
        if _invite_code_cache is not None:
            return _invite_code_cache

        arn = cfg.get("invite_secret_arn")
        if not arn:
            raise InviteNotConfigured("no invite secret is configured")
        try:
            sm = boto3.client("secretsmanager", region_name=cfg.get("region"))
            raw = sm.get_secret_value(SecretId=arn)["SecretString"]
        except Exception as exc:  # noqa: BLE001
            # Class name only. The message from a Secrets Manager failure can
            # quote the secret identifier but never the value; even so, nothing
            # from this call is echoed into a log.
            raise InviteNotConfigured(
                f"could not read the invite secret: {type(exc).__name__}"
            ) from exc

        # CDK generates {"code": "..."}. A hand-created secret holding the bare
        # code is accepted too, so an operator replacing the secret by hand does
        # not have to know the JSON shape.
        code = ""
        try:
            parsed = json.loads(raw)
        except ValueError:
            code = raw.strip()
        else:
            code = (
                str(parsed.get(INVITE_CODE_JSON_KEY, "")).strip()
                if isinstance(parsed, dict)
                else raw.strip()
            )
        if not code:
            raise InviteNotConfigured("the invite secret holds no code")
        _invite_code_cache = code
        return code


def _codes_match(submitted: str, expected: str) -> bool:
    """Constant-time comparison that also hides the expected code's length.

    hmac.compare_digest on the raw strings would return early for a length
    mismatch, which leaks the length of the real code through timing. Comparing
    fixed-width SHA-256 digests instead means every attempt costs the same
    regardless of what was submitted.
    """
    return hmac.compare_digest(
        hashlib.sha256(submitted.encode()).digest(),
        hashlib.sha256(expected.encode()).digest(),
    )


def _allowed_domains(cfg: dict) -> list[str]:
    raw = (cfg.get("invite_allowed_email_domains") or INVITE_ANY_DOMAIN).strip()
    if raw == INVITE_ANY_DOMAIN or not raw:
        return []
    return [d.strip().lower() for d in raw.split(",") if d.strip()]


def sign_up_mode(cfg: dict) -> str:
    """ "app" (POST /auth/register creates users) or "cognito" (native Cognito self sign-up)."""
    return "cognito" if cfg.get("sign_up_mode") == "cognito" else "app"


def invite_required(cfg: dict) -> bool:
    """True when this deployment was created with an invite code (-c inviteCode=true)."""
    return bool(cfg.get("invite_secret_arn"))


def _aws_error_code(exc: Exception) -> str:
    """The AWS error code for an exception raised by a boto3 client.

    botocore raises ClientError with the code inside the response, while the
    modelled exception classes are named after the code. Reading both means this
    module does not have to import botocore and a test double can raise a plainly
    named exception.
    """
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
        if code:
            return str(code)
    return type(exc).__name__


def _aws_error_message(exc: Exception, fallback: str) -> str:
    """The service message for an exception, bounded and flattened.

    Used only for InvalidParameterException, where Cognito's own wording (for
    example an unusable email address) is the most useful thing to show a person.
    It is still length-capped and newline-stripped before it goes into a response.
    """
    response = getattr(exc, "response", None)
    message = ""
    if isinstance(response, dict):
        message = str(response.get("Error", {}).get("Message", ""))
    if not message:
        message = str(exc)
    message = " ".join(message.split())
    # The client also strips a leading "InvalidPasswordException:" prefix, which
    # botocore does not put in the Message field but which some SDK paths do. It
    # is left alone here rather than stripped twice.
    return message[:INVITE_MAX_MESSAGE_LEN] or fallback


def register_user(email, invite_code) -> tuple[str, str]:
    """Create a user and have Cognito email them a temporary password.

    Returns (outcome, message) where outcome is one of the REGISTER_* constants.
    The invite code is never returned or logged.

    Order of checks matters. The email format and the optional domain allowlist
    are evaluated BEFORE the code is compared, so a wrong code always produces
    the same answer no matter what address it arrives with. Doing it the other way
    round would make the response an oracle: "domain not allowed" would confirm
    that the submitted code was correct.

    No password is accepted here. AdminCreateUser is called without
    TemporaryPassword and without MessageAction, so Cognito generates the
    temporary password and emails it. Being able to sign in with it is the proof
    that the caller owns the address, which is why marking email_verified true is
    honest; managed login then requires a new password (FORCE_CHANGE_PASSWORD).
    """
    cfg = config()

    email = (email or "").strip().lower() if isinstance(email, str) else ""
    invite_code = invite_code if isinstance(invite_code, str) else ""

    # The invite code is deliberately NOT part of this presence check. A missing
    # code has to arrive at the same outcome as a wrong one (REGISTER_BAD_CODE, 403),
    # because the client renders "invalid or missing invite code" as a single
    # state. An empty string simply fails the comparison below, so no special case
    # is needed and the check ordering described above is preserved.
    if not email:
        return REGISTER_BAD_REQUEST, "An email address is required."
    if len(email) > INVITE_MAX_EMAIL_LEN or not _EMAIL_RE.match(email):
        return REGISTER_BAD_REQUEST, "Enter a valid email address."
    if len(invite_code) > INVITE_MAX_CODE_LEN:
        return REGISTER_BAD_CODE, "That invite code is not valid."

    domain = email.rsplit("@", 1)[-1]
    allowed = _allowed_domains(cfg)
    if allowed and domain not in allowed:
        log.info("invite refused: email domain %s is not on the allowlist", domain)
        return (
            REGISTER_EMAIL_NOT_ALLOWED,
            "Registration is limited to approved email domains.",
        )

    if invite_required(cfg):
        try:
            expected = _invite_code(cfg)
        except InviteNotConfigured as exc:
            log.error("registration unavailable: %s", exc)
            return REGISTER_UNAVAILABLE, "Registration is not available on this deployment."
        if not _codes_match(invite_code, expected):
            # Fingerprint only, so repeated guesses are correlatable in the log
            # without the guesses themselves being in it.
            log.warning(
                "registration refused: bad invite code (sha256 %s) for domain %s",
                _code_fingerprint(invite_code),
                domain,
            )
            return REGISTER_BAD_CODE, "That invite code is not valid."

    region = cfg.get("region")
    try:
        idp = boto3.client("cognito-idp", region_name=region)
    except Exception as exc:  # noqa: BLE001
        log.error("invite failed: no cognito client: %s", type(exc).__name__)
        return REGISTER_UNAVAILABLE, "Registration is not available right now."

    try:
        idp.admin_create_user(
            UserPoolId=cfg["user_pool_id"],
            Username=email,
            UserAttributes=[
                {"Name": "email", "Value": email},
                # Safe to assert up front: the only way to use this account is to
                # sign in with the temporary password Cognito sends to this
                # address, so an address the caller does not own yields an
                # account nobody can enter. Verified is also what lets the user
                # reset a forgotten password later.
                {"Name": "email_verified", "Value": "true"},
            ],
            # No MessageAction and no TemporaryPassword: Cognito generates the
            # temporary password and sends the invitation email itself.
            DesiredDeliveryMediums=["EMAIL"],
        )
    except Exception as exc:  # noqa: BLE001 - classified below
        code = _aws_error_code(exc)
        if code == "UsernameExistsException":
            # Answered exactly like a new registration, so this public route is
            # not a user-existence oracle. The owner of the address already has
            # an account and can sign in or reset their password.
            log.info("registration for an existing address on domain %s", domain)
            return REGISTER_OK, REGISTER_OK_MESSAGE
        if code == "InvalidParameterException":
            log.info("registration refused: invalid parameter")
            return REGISTER_BAD_REQUEST, _aws_error_message(
                exc, "That registration request was rejected."
            )
        # Class name only: the message can carry the user pool id and the
        # operation name, neither of which belongs in a response to an
        # unauthenticated caller.
        log.error("registration failed on create: %s", code)
        return REGISTER_UNAVAILABLE, "Registration is not available right now."

    # Domain only. The full address is in the CloudTrail record for
    # AdminCreateUser, which is the durable audit trail; repeating it here would
    # put an address into application logs for no extra accountability.
    log.info("registration accepted: invited a user on domain %s", domain)
    return REGISTER_OK, REGISTER_OK_MESSAGE
