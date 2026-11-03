// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { RetryButton } from "./RetryButton";
import { ApiError } from "@/lib/api";

describe("RetryButton", () => {
  it("calls onRetry once and shows progress", async () => {
    let resolve: () => void = () => {};
    const onRetry = vi.fn(
      () =>
        new Promise<void>((r) => {
          resolve = r;
        }),
    );
    render(<RetryButton onRetry={onRetry} label="Retry scan" />);
    fireEvent.click(screen.getByRole("button", { name: "Retry scan" }));
    fireEvent.click(screen.getByRole("button", { name: /Retrying/ }));
    expect(onRetry).toHaveBeenCalledTimes(1);
    resolve();
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Retry scan" }).hasAttribute(
          "disabled",
        ),
      ).toBe(false),
    );
  });

  it("shows the error when the retry fails", async () => {
    render(
      <RetryButton
        onRetry={() =>
          Promise.reject(new Error("only FAILED scans can be retried"))
        }
        label="Retry"
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect((await screen.findByRole("alert")).textContent).toContain(
      "only FAILED scans can be retried",
    );
  });

  it("says the retry could not be queued on a final 503 and can be pressed again", async () => {
    const onRetry = vi.fn(() =>
      Promise.reject(new ApiError("Service Unavailable", 503)),
    );
    render(<RetryButton onRetry={onRetry} label="Retry" />);
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect((await screen.findByRole("alert")).textContent).toBe(
      "Could not queue the retry, try again.",
    );
    const button = screen.getByRole("button", { name: "Retry" });
    expect(button.hasAttribute("disabled")).toBe(false);
    fireEvent.click(button);
    await waitFor(() => expect(onRetry).toHaveBeenCalledTimes(2));
  });
});
