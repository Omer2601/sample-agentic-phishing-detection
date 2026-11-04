// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { usePolling } from "./usePolling";

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

async function flush() {
  await act(async () => {
    await Promise.resolve();
  });
}

describe("usePolling", () => {
  it("runs immediately and then on the interval", async () => {
    const task = vi.fn(async () => {});
    renderHook(() => usePolling(task, 2000, true));
    await flush();
    expect(task).toHaveBeenCalledTimes(1);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2000);
    });
    expect(task).toHaveBeenCalledTimes(2);
  });

  it("does nothing while disabled and stops when disabled", async () => {
    const task = vi.fn(async () => {});
    const { rerender } = renderHook(({ on }) => usePolling(task, 1000, on), {
      initialProps: { on: false },
    });
    await flush();
    expect(task).not.toHaveBeenCalled();
    rerender({ on: true });
    await flush();
    expect(task).toHaveBeenCalledTimes(1);
    rerender({ on: false });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(task).toHaveBeenCalledTimes(1);
  });

  it("keeps polling after a failed run and reports the error", async () => {
    const reportError = vi.fn();
    vi.stubGlobal("reportError", reportError);
    const task = vi
      .fn()
      .mockRejectedValueOnce(new Error("boom"))
      .mockResolvedValue(undefined);
    renderHook(() => usePolling(task, 1000, true));
    await flush();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(reportError).toHaveBeenCalledOnce();
    expect(task).toHaveBeenCalledTimes(2);
    vi.unstubAllGlobals();
  });

  it("stops on unmount", async () => {
    const task = vi.fn(async () => {});
    const { unmount } = renderHook(() => usePolling(task, 1000, true));
    await flush();
    unmount();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000);
    });
    expect(task).toHaveBeenCalledTimes(1);
  });
});
