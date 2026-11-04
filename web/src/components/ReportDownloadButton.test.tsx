// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

const startDownload = vi.fn();
vi.mock("@/lib/download", () => ({
  startDownload: (...a: unknown[]) => startDownload(...a),
}));

import { ApiError } from "@/lib/api";
import { ReportDownloadButton } from "./ReportDownloadButton";

describe("ReportDownloadButton", () => {
  it("fetches a fresh link on click and downloads it", async () => {
    const fetchLink = vi.fn(async () => ({
      url: "https://s3.example/r.html",
      expires_in: 900,
    }));
    render(<ReportDownloadButton fetchLink={fetchLink} />);
    fireEvent.click(screen.getByRole("button", { name: "Download report" }));
    await waitFor(() =>
      expect(startDownload).toHaveBeenCalledWith("https://s3.example/r.html"),
    );
    expect(fetchLink).toHaveBeenCalledTimes(1);
  });

  it("shows the API's reason when there is no report yet", async () => {
    const fetchLink = vi.fn(async () => {
      throw new ApiError("the scan has not completed", 409);
    });
    render(<ReportDownloadButton fetchLink={fetchLink} />);
    fireEvent.click(screen.getByRole("button", { name: "Download report" }));
    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toBe(
        "the scan has not completed",
      ),
    );
  });
});
