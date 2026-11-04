// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { AuthLayout } from "@/components/auth/AuthLayout";
import { TextField } from "@/components/auth/Fields";
import { fieldElementId } from "@/components/auth/fieldIds";
import { StatusBanner, type StatusMessage } from "@/components/auth/StatusBanner";
import { CheckIcon } from "@/components/auth/icons";
import { Button, Spinner } from "@/components/ui";
import {
  COGNITO_SIGN_UP_PATH,
  SIGN_IN_PATH,
  SUCCESS_MESSAGE,
  loadRegistrationConfig,
  submitRegistration,
  validateEmail,
  validateInviteCode,
  type RegistrationField,
} from "@/lib/registration";

/**
 * REGISTRATION.
 *
 * This is the one identity screen the app owns. Sign-IN is deliberately NOT
 * reimplemented here: the "Sign in" links are plain anchors to SIGN_IN_PATH, a
 * server route that redirects to Cognito's branded managed login. That redirect
 * is the contract, so these must stay anchors and never become client-side
 * routes or an in-page credential form.
 *
 * There are no social sign-in buttons. The reference design has them, but this
 * user pool has no federated identity providers configured, so a Google or
 * Facebook button would be a control that cannot work.
 *
 * No password is asked for. The server creates the user and Cognito emails a
 * temporary password; signing in with it proves the caller owns the inbox, and
 * managed login then makes them choose their own. The invite code lives only in
 * component state and in the request body: nothing is written to storage, put
 * in a URL, or logged.
 *
 * There is no automatic redirect after submitting: the user has to fetch the
 * temporary password from their inbox first, so the page waits for them.
 */

type FieldName = "email" | "inviteCode";

type FieldErrors = Partial<Record<FieldName, string | null>>;

/** Order used both for validation and for deciding which field to focus. */
const FIELD_ORDER: FieldName[] = ["email", "inviteCode"];

/** Server-side field names map onto our slightly different local names. */
function localField(field: RegistrationField): FieldName | null {
  if (field === "email") return "email";
  if (field === "inviteCode") return "inviteCode";
  return null;
}

function focusField(name: FieldName) {
  // Focus by id rather than through a ref map: the ids are stable and owned by
  // Fields.tsx, and this keeps the form from carrying four refs whose only job
  // is one call on the failure path.
  document.getElementById(fieldElementId(name))?.focus();
}

export function RegisterPage() {
  const [email, setEmail] = useState("");
  const [inviteCode, setInviteCode] = useState("");

  const [errors, setErrors] = useState<FieldErrors>({});
  const [status, setStatus] = useState<StatusMessage | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [created, setCreated] = useState(false);
  // null while loading; the form stays disabled until the server says which fields it needs.
  const [inviteRequired, setInviteRequired] = useState<boolean | null>(null);
  const [cognitoSignUp, setCognitoSignUp] = useState(false);
  const [configError, setConfigError] = useState<string | null>(null);
  useEffect(() => {
    loadRegistrationConfig()
      .then((cfg) => {
        setInviteRequired(cfg.inviteRequired);
        setCognitoSignUp(cfg.signUpMode === "cognito");
      })
      .catch((err: unknown) =>
        setConfigError(
          err instanceof Error
            ? err.message
            : "Registration settings could not be loaded.",
        ),
      );
  }, []);

  /**
   * Keyboard focus is on the submit button when a submit starts, and disabling
   * that button while the request runs drops focus to the body. When the failure
   * belongs to no particular field there is nowhere better to send focus, so it
   * goes back to the button the user pressed. The counter (rather than a boolean)
   * is what makes a second failed attempt re-run the effect.
   */
  const submitRef = useRef<HTMLButtonElement>(null);
  const [restoreFocus, setRestoreFocus] = useState(0);
  useEffect(() => {
    if (restoreFocus > 0) submitRef.current?.focus();
  }, [restoreFocus]);

  /**
   * Only re-validate a field the user has already been told about, so the form
   * does not shout "enter your email address" at someone who is halfway through
   * typing it. Errors appear on submit, then correct themselves live.
   */
  const revise = useCallback((name: FieldName, message: string | null) => {
    setErrors((prev) => (name in prev ? { ...prev, [name]: message } : prev));
  }, []);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (submitting) return;

    const found: FieldErrors = {
      email: validateEmail(email),
      inviteCode: inviteRequired ? validateInviteCode(inviteCode) : null,
    };
    setErrors(found);

    const firstBad = FIELD_ORDER.find((name) => found[name]);
    if (firstBad) {
      setStatus({
        tone: "error",
        text: "Some details need fixing before your account can be created.",
      });
      focusField(firstBad);
      return;
    }

    setSubmitting(true);
    setStatus({ tone: "info", text: "Creating your account." });

    const outcome = await submitRegistration({
      email: email.trim(),
      inviteCode: inviteRequired ? inviteCode.trim() : undefined,
    });

    setSubmitting(false);

    if (outcome.kind === "success") {
      setStatus({ tone: "success", text: outcome.message });
      setCreated(true);
      return;
    }

    // Announce every refusal in the live region, and additionally pin it under
    // the field responsible when the outcome identifies one.
    setStatus({ tone: "error", text: outcome.message });
    const target = localField(outcome.field);
    if (target) {
      setErrors((prev) => ({ ...prev, [target]: outcome.message }));
      focusField(target);
    } else {
      setRestoreFocus((n) => n + 1);
    }
  };

  return (
    <AuthLayout>
      {/* The one live region that announces every submit result. */}
      <StatusBanner status={status} />

      {cognitoSignUp ? (
        // Cognito owns sign-up on this deployment (-c signUpMode=cognito); the
        // server route redirects to its managed sign-up page.
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight text-fg sm:text-4xl">
            Create your account
          </h1>
          <p className="mt-2 text-sm leading-relaxed text-fg-subtle">
            Sign-up happens on the secure Cognito page. You will verify your email
            address, then come back here signed in.
          </p>
          <a
            href={COGNITO_SIGN_UP_PATH}
            className="mt-6 inline-flex h-12 items-center justify-center rounded-xl border border-transparent bg-accent px-6 text-base font-medium text-white shadow-xs shadow-accent/30 transition-all hover:brightness-110"
          >
            Create an account
          </a>
        </div>
      ) : created ? (
        <div>
          <span className="mb-5 inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-safe/15 text-safe">
            <CheckIcon className="h-6 w-6" />
          </span>
          <h1 className="text-3xl font-extrabold tracking-tight text-fg">Check your email</h1>
          <p className="mt-2 text-sm leading-relaxed text-fg-subtle">{SUCCESS_MESSAGE}</p>
          <a
            href={SIGN_IN_PATH}
            className="mt-6 inline-flex h-12 items-center justify-center rounded-xl border border-transparent bg-accent px-6 text-base font-medium text-white shadow-xs shadow-accent/30 transition-all hover:brightness-110"
          >
            Continue to sign in
          </a>
        </div>
      ) : (
        <>
          <header>
            <h1 className="text-3xl font-extrabold tracking-tight text-fg sm:text-4xl">
              Create your account
            </h1>
            <p className="mt-2 text-sm leading-relaxed text-fg-subtle">
              {inviteRequired
                ? "This deployment is invite only. Enter the code you were given."
                : "Create an account to use the analyst console."}
            </p>
          </header>

          <form onSubmit={handleSubmit} noValidate className="mt-8 space-y-5">
            {configError && (
              <p className="text-sm text-danger" role="alert">
                {configError}
              </p>
            )}
            <TextField
              name="email"
              label="Email address"
              type="email"
              inputMode="email"
              autoComplete="email"
              autoCapitalize="none"
              spellCheck={false}
              placeholder="you@example.com"
              value={email}
              disabled={submitting}
              error={errors.email}
              onChange={(e) => {
                setEmail(e.target.value);
                revise("email", validateEmail(e.target.value));
              }}
            />

            {inviteRequired && (
              <TextField
                name="inviteCode"
                label="Invite code"
                type="text"
                autoComplete="off"
                // Not "characters": a phone keyboard auto-capitalising a lowercase
                // code would break a case-sensitive comparison on the server.
                autoCapitalize="none"
                spellCheck={false}
                placeholder="Paste the code from your invite"
                value={inviteCode}
                disabled={submitting}
                error={errors.inviteCode}
                onChange={(e) => {
                  setInviteCode(e.target.value);
                  revise("inviteCode", validateInviteCode(e.target.value));
                }}
              />
            )}

            <Button
              ref={submitRef}
              type="submit"
              size="lg"
              className="w-full justify-center"
              disabled={submitting || inviteRequired === null}
              aria-busy={submitting}
            >
              {submitting ? (
                <>
                  <Spinner className="h-4 w-4 text-white" />
                  Creating account
                </>
              ) : (
                "Create account"
              )}
            </Button>
          </form>

          <p className="mt-6 text-center text-sm text-fg-subtle">
            Already have an account?{" "}
            {/*
             * A plain anchor, not a Link: sign-in is a server route that
             * redirects to the Cognito managed login page, so this has to be a
             * real navigation rather than a client-side route change.
             */}
            <a href={SIGN_IN_PATH} className="font-semibold text-accent hover:underline">
              Sign in
            </a>
          </p>

          <p className="mt-2 text-center text-xs text-muted">
            Not sure you need an account?{" "}
            <Link to="/welcome" className="underline hover:text-fg-subtle">
              Back to the start
            </Link>
          </p>
        </>
      )}
    </AuthLayout>
  );
}
