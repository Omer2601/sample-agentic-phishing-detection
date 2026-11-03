// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { afterEach, describe, expect, it, vi } from "vitest";
import { loadRegistrationConfig } from "./registration";

afterEach(() => {
  vi.unstubAllGlobals();
});

function serve(body: unknown) {
  vi.stubGlobal("fetch", async () => Response.json(body));
}

describe("loadRegistrationConfig", () => {
  it("reads the invite flag and cognito sign-up mode", async () => {
    serve({ invite_required: true, sign_up_mode: "cognito" });
    await expect(loadRegistrationConfig()).resolves.toEqual({
      inviteRequired: true,
      signUpMode: "cognito",
    });
  });

  it("defaults to app mode without an invite", async () => {
    serve({});
    await expect(loadRegistrationConfig()).resolves.toEqual({
      inviteRequired: false,
      signUpMode: "app",
    });
  });
});
