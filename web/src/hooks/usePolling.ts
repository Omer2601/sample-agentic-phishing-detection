// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useEffect, useRef } from "react";

/**
 * Run `task` now and then every `intervalMs` after each run settles, while
 * `enabled` is true. Scheduling after settle (not setInterval) means a slow API
 * never stacks overlapping requests.
 *
 * Tasks own their error state. A task that still rejects is reported through the
 * platform's reportError, so it shows up as an uncaught error in the console, and
 * polling continues: one failed poll must not freeze a batch view.
 */
export function usePolling(
  task: () => Promise<void>,
  intervalMs: number,
  enabled: boolean,
): void {
  const taskRef = useRef(task);
  useEffect(() => {
    taskRef.current = task;
  });

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const schedule = () => {
      if (!cancelled) timer = setTimeout(tick, intervalMs);
    };
    const tick = () => {
      taskRef.current().then(schedule, (err: unknown) => {
        globalThis.reportError?.(err);
        schedule();
      });
    };
    tick();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [enabled, intervalMs]);
}
