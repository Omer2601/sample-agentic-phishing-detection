// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";

const startBatch = vi.fn();
const requestUpload = vi.fn();
const upload = vi.fn();
const refresh = vi.fn(async () => {});

vi.mock("@/lib/api", () => ({
  api: {
    startBatch: (...a: unknown[]) => startBatch(...a),
    requestUpload: (...a: unknown[]) => requestUpload(...a),
  },
}));
vi.mock("@/lib/http", () => ({
  uploadToPresignedPost: (...a: unknown[]) => upload(...a),
}));
vi.mock("@/hooks/useActiveBatches", () => ({
  useActiveBatches: () => ({
    batches: [],
    active: [],
    loaded: true,
    error: null,
    refresh,
  }),
}));

import { BatchPage } from "./BatchPage";

const urls = (n: number) =>
  Array.from({ length: n }, (_, i) => `https://site${i}.example`).join("\n");

function renderPage() {
  render(
    <MemoryRouter initialEntries={["/batch"]}>
      <Routes>
        <Route path="/batch" element={<BatchPage />} />
        <Route path="/batch/:batchId" element={<p>detail page</p>} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  startBatch.mockReset();
  requestUpload.mockReset();
  upload.mockReset();
});

describe("BatchPage", () => {
  it("sends up to 50 URLs as JSON", async () => {
    startBatch.mockResolvedValue({ batch_id: "b-1" });
    renderPage();
    fireEvent.change(screen.getByLabelText(/URLs/), {
      target: { value: urls(5) },
    });
    fireEvent.click(screen.getByRole("button", { name: /Scan 5 URLs/ }));
    await waitFor(() => expect(screen.getByText("detail page")).toBeTruthy());
    expect(startBatch).toHaveBeenCalledWith(
      expect.arrayContaining(["https://site0.example"]),
    );
    expect(upload).not.toHaveBeenCalled();
  });

  it("uploads larger lists to S3 and never through the JSON body", async () => {
    requestUpload.mockResolvedValue({
      batch_id: "b-2",
      upload_url: "https://s3",
      upload_fields: { key: "k" },
    });
    upload.mockResolvedValue(undefined);
    renderPage();
    fireEvent.change(screen.getByLabelText(/URLs/), {
      target: { value: urls(120) },
    });
    fireEvent.click(screen.getByRole("button", { name: /Scan 120 URLs/ }));
    await waitFor(() => expect(screen.getByText("detail page")).toBeTruthy());
    expect(requestUpload).toHaveBeenCalledWith(120);
    expect(upload).toHaveBeenCalledWith(
      "https://s3",
      { key: "k" },
      expect.any(Blob),
      "b-2.csv",
    );
    expect(startBatch).not.toHaveBeenCalled();
    expect(refresh).toHaveBeenCalled();
  });

  it("blocks more than 200 URLs in the UI and points at the API", () => {
    renderPage();
    fireEvent.change(screen.getByLabelText(/URLs/), {
      target: { value: urls(201) },
    });
    expect(screen.getByText(/at most 200 URLs/)).toBeTruthy();
    expect(
      screen
        .getByRole("button", { name: /Scan 201 URLs/ })
        .hasAttribute("disabled"),
    ).toBe(true);
  });

  it("reports invalid and duplicate rows before submitting", () => {
    renderPage();
    fireEvent.change(screen.getByLabelText(/URLs/), {
      target: { value: "https://a.example\nhttps://a.example\nnot a url" },
    });
    expect(screen.getByText(/1 duplicate/)).toBeTruthy();
    expect(screen.getByText(/1 invalid/)).toBeTruthy();
  });
});
