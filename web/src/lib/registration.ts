// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
/**
 * REGISTRATION LOGIC (pure, testable) + the single call the page makes.
 *
 * Sign-IN is not implemented here and must not be: the app hands the browser to
 * Cognito's branded managed login at SIGN_IN_PATH, a server route that performs
 * the OIDC authorization-code redirect (web/server/auth.py).
 *
 * Registration asks for an email address (and an invite code when the
 * deployment requires one) and nothing else. The server creates the user and
 * Cognito emails a temporary password; signing in with it proves the caller owns
 * the inbox, and managed login then makes the user choose their own password. So
 * this SPA never handles a password at all.
 *
 * The response mapper classifies on an explicit code/message when one is
 * present and falls back to the status code, so it stays correct across small
 * backend wording changes. An address that already has an account gets the same
 * success response as a new one, by design.
 *
 * Nothing here logs, stores, or persists the invite code. It exists only in
 * React state and in the request body.
 */
import { PayloadHashUnavailableError } from "./payloadHash";
import { fetchWithPayloadHash } from "./http";

/** Server route that starts the Cognito managed-login redirect. */
export const SIGN_IN_PATH = "/auth/login";

/** Same-origin endpoint that creates the user (and checks an invite code when required). */
export const REGISTER_PATH = "/auth/register";
/** Public endpoint that says which registration fields this deployment needs. */
export const CONFIG_PATH = "/auth/config";

/* ---- Field validation ---------------------------------------------------- */

/**
 * Deliberately loose email check. The authoritative validation is Cognito's, and
 * an over-strict client pattern rejects addresses that are perfectly valid; this
 * only catches the obvious typo before a round trip.
 */
export function validateEmail(raw: string): string | null {
  const value = raw.trim();
  if (!value) return "Enter your email address.";
  if (/\s/.test(value)) return "An email address cannot contain spaces.";
  const parts = value.split("@");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return "Enter a valid email address, for example you@example.com.";
  }
  if (!parts[1].includes(".") || parts[1].startsWith(".") || parts[1].endsWith(".")) {
    return "Enter a valid email address, for example you@example.com.";
  }
  return null;
}

export function validateInviteCode(raw: string): string | null {
  if (!raw.trim()) return "Enter the invite code you were given.";
  return null;
}

/* ---- Response mapping ---------------------------------------------------- */

export type RegistrationOutcomeKind =
  | "success"
  | "invalid-invite"
  | "rate-limited"
  | "error";

/** Which input the message belongs under, or null for a form-level message. */
export type RegistrationField = "email" | "inviteCode" | null;

export interface RegistrationOutcome {
  kind: RegistrationOutcomeKind;
  field: RegistrationField;
  message: string;
}

export const SUCCESS_MESSAGE =
  "We emailed you a temporary password. Sign in with it, then choose your own password.";
const NETWORK_MESSAGE = "We could not reach the server. Check your connection and try again.";
const GENERIC_MESSAGE = "We could not create your account just now. Please try again in a moment.";
/**
 * Shown on any 429: the edge WAF RegisterRateLimit rule (10 POSTs per 5 minutes per
 * IP, body {"error":"too_many_registrations"}) and the server's own limiter. The
 * limit is per IP, so it says "your network": people behind one NAT share it.
 */
const RATE_LIMIT_MESSAGE =
  "Too many sign-up attempts from your network, try again in a few minutes.";
const INVITE_MESSAGE =
  "That invite code is not valid. Check it with whoever invited you, then try again.";
const UNWIRED_MESSAGE =
  "Registration is not available on this server right now. Please try again later.";
/**
 * Shown when the browser cannot compute the CloudFront OAC payload hash the POST
 * needs (see lib/payloadHash.ts). Distinct from the network message on purpose:
 * the fix is the page's own origin, not the user's connection, and calling it a
 * connectivity problem would send them to retry forever.
 */
const INSECURE_CONTEXT_MESSAGE =
  "This browser could not secure the request. Open the app over https, then try again.";

/** Longest server message we will render, so one long string cannot wreck the layout. */
const MAX_SERVER_MESSAGE = 200;

/**
 * Pull a classification code and a human message out of whatever envelope the
 * endpoint uses. Several shapes are accepted on purpose: this SPA is the client
 * of a small first-party route, and tolerating `error` vs `message` vs `detail`
 * is cheaper than coupling the UI to one spelling.
 */
function readEnvelope(body: unknown): { code: string; message: string } {
  if (!body || typeof body !== "object") return { code: "", message: "" };
  const b = body as Record<string, unknown>;
  const str = (v: unknown) => (typeof v === "string" ? v : "");
  const code = str(b.code) || str(b.error_code) || str(b.errorCode) || str(b.error);
  const message = str(b.message) || str(b.detail) || str(b.error_description) || str(b.error);
  return { code, message };
}

/**
 * Tidy a server string for display: collapse whitespace, drop an AWS exception
 * prefix ("InvalidParameterException: ...") that means nothing to a user, and cap
 * the length.
 */
function humaniseServerMessage(raw: string): string {
  const collapsed = raw.replace(/\s+/g, " ").trim();
  const stripped = collapsed.replace(/^[A-Za-z]+(?:Exception|Error):\s*/, "");
  if (stripped.length <= MAX_SERVER_MESSAGE) return stripped;
  return `${stripped.slice(0, MAX_SERVER_MESSAGE).trimEnd()}...`;
}

/**
 * Map an /invite response onto one outcome with a field to blame.
 *
 * There is no "email already registered" outcome: the server answers an
 * existing address exactly like a new one, so this route cannot be used to find
 * out who has an account.
 *
 * 5xx text is never shown: it can carry stack detail and says nothing a user can
 * act on, so it collapses to the generic message.
 */
export function mapRegistrationResponse(
  status: number,
  body: unknown,
  contentType = "",
): RegistrationOutcome {
  if (status >= 200 && status < 300) {
    // A 2xx carrying HTML is not a created account: it is the SPA's own
    // index.html coming back from a history fallback, which is what happens when
    // /invite is not wired up on the tier serving the app (the dev server only
    // proxies /api/*). Reporting that as success would tell a user their account
    // exists when nothing was created.
    if (contentType.toLowerCase().includes("text/html")) {
      return { kind: "error", field: null, message: UNWIRED_MESSAGE };
    }
    return { kind: "success", field: null, message: SUCCESS_MESSAGE };
  }

  const { code, message } = readEnvelope(body);
  const hay = `${code} ${message}`.toLowerCase();
  const server = humaniseServerMessage(message);

  if (
    status === 429 ||
    hay.includes("too many") ||
    hay.includes("rate limit") ||
    hay.includes("ratelimit") ||
    hay.includes("throttl")
  ) {
    return { kind: "rate-limited", field: null, message: RATE_LIMIT_MESSAGE };
  }

  if (status >= 500) {
    return { kind: "error", field: null, message: GENERIC_MESSAGE };
  }

  if (
    hay.includes("invite") ||
    hay.includes("invitation") ||
    hay.includes("invalid_code") ||
    hay.includes("missing_code")
  ) {
    return { kind: "invalid-invite", field: "inviteCode", message: INVITE_MESSAGE };
  }

  if (status === 403) {
    // An unexplained refusal on this route is an invite problem far more often
    // than anything else, and the invite field is the one the user can fix.
    return { kind: "invalid-invite", field: "inviteCode", message: INVITE_MESSAGE };
  }

  return { kind: "error", field: null, message: server || GENERIC_MESSAGE };
}

/* ---- The call ------------------------------------------------------------ */

export interface RegistrationInput {
  email: string;
  /** Only sent when the deployment requires an invite code. */
  inviteCode?: string;
}

/**
 * POST /auth/register, same origin.
 *
 * This does not go through the `api` transport in lib/api.ts on purpose: that
 * seam is the SigV4-signed /api/* path to API Gateway, while /auth/register is a route
 * on the first-party UI tier that never reaches the scanning API. Keeping it
 * separate stops an unauthenticated registration call from being modelled as a
 * signed backend call.
 *
 * The invite code appears only in the request body. It is never logged, never
 * stored, and never put in a URL.
 *
 * It does go through fetchWithPayloadHash (lib/http.ts) like every other request,
 * because /auth/register is a POST and the app is served through CloudFront with Origin
 * Access Control: the caller has to send the SHA-256 of the body in
 * x-amz-content-sha256 or CloudFront refuses it with a bare 403. That is a
 * transport concern, unrelated to which tier answers the route.
 */
export async function submitRegistration(
  input: RegistrationInput,
): Promise<RegistrationOutcome> {
  let res: Response;
  try {
    res = await fetchWithPayloadHash(REGISTER_PATH, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({
        email: input.email,
        ...(input.inviteCode ? { inviteCode: input.inviteCode } : {}),
      }),
    });
  } catch (err) {
    // A failed payload hash means nothing was sent, and it is not a reachability
    // problem, so it gets its own wording. Both paths still return an outcome
    // rather than throwing: the page awaits this and would otherwise leave its
    // submit button spinning forever.
    if (err instanceof PayloadHashUnavailableError) {
      return { kind: "error", field: null, message: INSECURE_CONTEXT_MESSAGE };
    }
    return { kind: "error", field: null, message: NETWORK_MESSAGE };
  }

  let body: unknown;
  try {
    body = await res.json();
  } catch {
    body = undefined;
  }
  return mapRegistrationResponse(res.status, body, res.headers?.get("content-type") ?? "");
}

/**
 * Whether this deployment asks for an invite code, and who owns sign-up. The
 * server decides: an invite is required only when the operator deployed with
 * -c inviteCode=true, and -c signUpMode=cognito hands sign-up to Cognito.
 */
export type SignUpMode = "app" | "cognito";

/** Server route that redirects to Cognito managed sign-up (cognito mode only). */
export const COGNITO_SIGN_UP_PATH = "/auth/signup";

export async function loadRegistrationConfig(): Promise<{
  inviteRequired: boolean;
  signUpMode: SignUpMode;
}> {
  const res = await fetchWithPayloadHash(CONFIG_PATH, {
    credentials: "same-origin",
  });
  if (!res.ok)
    throw new Error(
      `Registration settings could not be loaded (HTTP ${res.status}).`,
    );
  const body = (await res.json()) as {
    invite_required?: unknown;
    sign_up_mode?: unknown;
  };
  return {
    inviteRequired: body.invite_required === true,
    signUpMode: body.sign_up_mode === "cognito" ? "cognito" : "app",
  };
}
