// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/hooks/useTheme";

const loadRegistrationConfig = vi.fn();
const submitRegistration = vi.fn();
vi.mock("@/lib/registration", async (orig) => ({
  ...(await orig<typeof import("@/lib/registration")>()),
  loadRegistrationConfig: () => loadRegistrationConfig(),
  submitRegistration: (input: unknown) => submitRegistration(input),
}));

import { RegisterPage } from "./RegisterPage";

function renderPage() {
  render(
    <ThemeProvider>
      <MemoryRouter>
        <RegisterPage />
      </MemoryRouter>
    </ThemeProvider>,
  );
}

describe("RegisterPage", () => {
  it("hides the invite field when the deployment does not require one", async () => {
    loadRegistrationConfig.mockResolvedValue({
      inviteRequired: false,
      signUpMode: "app",
    });
    renderPage();
    await waitFor(() =>
      expect(screen.getByLabelText("Email address")).toBeTruthy(),
    );
    expect(screen.queryByLabelText("Invite code")).toBeNull();
  });

  it("asks for the invite code when required", async () => {
    loadRegistrationConfig.mockResolvedValue({
      inviteRequired: true,
      signUpMode: "app",
    });
    renderPage();
    await waitFor(() =>
      expect(screen.getByLabelText("Invite code")).toBeTruthy(),
    );
  });

  it("hands off to Cognito sign-up in cognito mode instead of showing the form", async () => {
    loadRegistrationConfig.mockResolvedValue({
      inviteRequired: false,
      signUpMode: "cognito",
    });
    renderPage();
    await waitFor(() =>
      expect(
        screen
          .getByRole("link", { name: "Create an account" })
          .getAttribute("href"),
      ).toBe("/auth/signup"),
    );
    expect(screen.queryByLabelText("Email address")).toBeNull();
  });

  it("asks only for an email address, never a password", async () => {
    loadRegistrationConfig.mockResolvedValue({
      inviteRequired: false,
      signUpMode: "app",
    });
    renderPage();
    await waitFor(() =>
      expect(screen.getByLabelText("Email address")).toBeTruthy(),
    );
    expect(screen.queryByLabelText(/password/i)).toBeNull();
    expect(document.querySelector('input[type="password"]')).toBeNull();
  });

  it("tells the user a temporary password was emailed after submitting", async () => {
    loadRegistrationConfig.mockResolvedValue({
      inviteRequired: false,
      signUpMode: "app",
    });
    submitRegistration.mockResolvedValue({
      kind: "success",
      field: null,
      message: "ignored",
    });
    renderPage();
    const email = await screen.findByLabelText("Email address");
    fireEvent.change(email, { target: { value: "new@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Create account" }));
    await waitFor(() =>
      expect(
        screen.getAllByText(/We emailed you a temporary password/).length,
      ).toBeGreaterThan(0),
    );
    expect(submitRegistration).toHaveBeenCalledWith({
      email: "new@example.com",
      inviteCode: undefined,
    });
  });
});

describe("RegisterPage rate limit", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("explains a WAF 429 as too many sign-up attempts from the network", async () => {
    const real = await vi.importActual<typeof import("@/lib/registration")>(
      "@/lib/registration",
    );
    loadRegistrationConfig.mockResolvedValue({
      inviteRequired: false,
      signUpMode: "app",
    });
    submitRegistration.mockImplementation((input) =>
      real.submitRegistration(input as { email: string }),
    );
    // The edge WAF RegisterRateLimit rule's custom response (infra edge_waf.py).
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response('{"error":"too_many_registrations"}', {
            status: 429,
            headers: { "content-type": "application/json" },
          }),
      ),
    );
    renderPage();
    const email = await screen.findByLabelText("Email address");
    fireEvent.change(email, { target: { value: "new@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Create account" }));
    await waitFor(() =>
      expect(
        screen.getAllByText(
          /Too many sign-up attempts from your network, try again in a few minutes/,
        ).length,
      ).toBeGreaterThan(0),
    );
  });
});

/*
 * The real lib/registration request and response mapping. These used to live in
 * lib/registration.test.ts (manifest row 151: DELETE); they run here against the
 * unmocked module so the page test file owns every registration assertion.
 */
describe("registration request and response mapping", () => {
  afterEach(() => vi.unstubAllGlobals());

  async function actual() {
    return vi.importActual<typeof import("@/lib/registration")>("@/lib/registration");
  }

  it("sends the email (and invite code) but no password", async () => {
    const { submitRegistration: realSubmit } = await actual();
    const fetchMock = vi.fn(
      async () =>
        new Response(JSON.stringify({ code: "created", message: "m" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await realSubmit({ email: "a@example.com", inviteCode: "c0de" });
    const init = (fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect(JSON.parse(String(init.body))).toEqual({
      email: "a@example.com",
      inviteCode: "c0de",
    });
  });

  it("reports a 2xx as an emailed temporary password", async () => {
    const { mapRegistrationResponse } = await actual();
    const out = mapRegistrationResponse(200, { code: "created" }, "application/json");
    expect(out.kind).toBe("success");
    expect(out.message).toMatch(/We emailed you a temporary password/);
  });
});
