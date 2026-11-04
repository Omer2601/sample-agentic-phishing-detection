// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, edgeRejectionMessage } from "./api";

type Seen = { url: string; init?: RequestInit };

function stubFetch(response: Response): Seen[] {
  const seen: Seen[] = [];
  vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
    seen.push({ url, init });
    return response.clone();
  });
  return seen;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("api client", () => {
  it("starts a scan with a JSON body on same-origin /api", async () => {
    const seen = stubFetch(Response.json({ scan_id: "s-1" }, { status: 202 }));
    await expect(api.startScan("https://a.example")).resolves.toEqual({
      scan_id: "s-1",
    });
    expect(seen[0].url).toBe("/api/scan");
    expect(seen[0].init?.method).toBe("POST");
    expect(JSON.parse(String(seen[0].init?.body))).toEqual({
      url: "https://a.example",
    });
    expect(seen[0].init?.credentials).toBe("same-origin");
  });

  it("requests an upload ticket for UI batches", async () => {
    const seen = stubFetch(
      Response.json(
        { batch_id: "b-1", upload_url: "https://s3", upload_fields: {} },
        { status: 202 },
      ),
    );
    await api.requestUpload(120);
    expect(JSON.parse(String(seen[0].init?.body))).toEqual({
      upload: true,
      count: 120,
      source: "ui",
    });
  });

  it("encodes ids and pagination tokens", async () => {
    const seen = stubFetch(Response.json({ batch: {}, items: [], next: null }));
    await api.getBatch("a/b", "tok+1");
    expect(seen[0].url).toBe("/api/batches/a%2Fb?limit=200&next=tok%2B1");
  });

  it("asks for a scan report link and returns the presigned URL", async () => {
    const seen = stubFetch(
      Response.json({ url: "https://s3.example/r.html", expires_in: 900 }),
    );
    await expect(api.getScanReport("s/1")).resolves.toEqual({
      url: "https://s3.example/r.html",
      expires_in: 900,
    });
    expect(seen[0].url).toBe("/api/scans/s%2F1/report");
    expect(seen[0].init?.method ?? "GET").toBe("GET");
  });

  it("asks for a batch report link", async () => {
    const seen = stubFetch(
      Response.json({ url: "https://s3.example/b.html", expires_in: 900 }),
    );
    await api.getBatchReport("b-1");
    expect(seen[0].url).toBe("/api/batches/b-1/report");
  });

  it("builds the CSV export link without fetching", () => {
    expect(api.statsExportUrl("30d")).toBe("/api/stats/export?range=30d");
  });

  it("surfaces the API error message and status", async () => {
    stubFetch(
      Response.json({ error: "Maximum 200 URLs per batch" }, { status: 400 }),
    );
    const err = await api.startBatch(["x"]).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(400);
    expect((err as ApiError).message).toBe("Maximum 200 URLs per batch");
  });

  it("replaces an intermediary HTML error body with a short message", async () => {
    stubFetch(new Response("<html>blocked</html>", { status: 403 }));
    await expect(api.getHistory()).rejects.toThrow(edgeRejectionMessage(403));
  });

  it("maps the phishing feed", async () => {
    stubFetch(
      Response.json({
        items: [
          {
            url: "https://x.example",
            host: "x.example",
            risk: "high",
            label: "x",
            source: "feed",
          },
        ],
        groups: [],
        attribution: "OpenPhish",
        live_count: 1,
        cached: true,
        warning: "",
      }),
    );
    const feed = await api.getSuggestions(5);
    expect(feed.liveCount).toBe(1);
    expect(feed.items[0].host).toBe("x.example");
  });
});

describe("retry endpoints", () => {
  it("posts to the scan and batch retry routes", async () => {
    const calls: string[] = [];
    vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
      calls.push(`${init.method} ${url}`);
      return new Response(JSON.stringify({ scan_id: "s1", status: "PENDING", batch_id: "b1", retried: 2 }),
        { status: 202, headers: { "Content-Type": "application/json" } });
    });
    await api.retryScan("s1");
    expect((await api.retryFailed("b1")).retried).toBe(2);
    expect(calls).toEqual(["POST /api/scans/s1/retry", "POST /api/batches/b1/retry-failed"]);
  });
});
