// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { Link } from "react-router-dom";
import { AuthLayout } from "@/components/auth/AuthLayout";
import { SIGN_IN_PATH } from "@/lib/registration";

/**
 * Landing state for a visitor with no session.
 *
 * Its only job is to route a person to the right place: existing users to
 * Cognito's managed login, new users to registration. The primary control is
 * a plain anchor to SIGN_IN_PATH, a server route that performs the OIDC redirect
 * to the branded Cognito page. No credential field appears here on purpose;
 * this app never handles a sign-in password.
 */
export function WelcomePage() {
  return (
    <AuthLayout>
      <h1 className="text-3xl font-extrabold tracking-tight text-fg sm:text-4xl">
        Welcome
      </h1>
      <p className="mt-2 text-sm leading-relaxed text-fg-subtle">
        The analyst console for the Agentic Phishing URL Detection on Amazon Bedrock AgentCore. Sign-in is handled
        by Amazon Cognito, where you can add an authenticator app for
        multi-factor authentication.
      </p>

      <div className="mt-8 space-y-3">
        <a
          href={SIGN_IN_PATH}
          className="flex h-12 w-full items-center justify-center rounded-xl border border-transparent bg-accent px-6 text-base font-medium text-white shadow-xs shadow-accent/30 transition-all hover:brightness-110"
        >
          Sign in
        </a>
        <Link
          to="/register"
          className="flex h-12 w-full items-center justify-center rounded-xl border border-border bg-surface-2 px-6 text-base font-medium text-fg transition-colors hover:bg-surface-2/70"
        >
          Create an account
        </Link>
      </div>

      <p className="mt-6 text-xs leading-relaxed text-muted">
        Some deployments ask for an invite code at registration. Your administrator can tell you.
      </p>
    </AuthLayout>
  );
}
