// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { api } from "@/lib/api";
import { isBatchActive } from "@/lib/batch";
import type { BatchRecord } from "@/lib/types";
import { usePolling } from "./usePolling";

export const BATCH_POLL_MS = 2000;

interface ActiveBatchesValue {
  batches: BatchRecord[];
  active: BatchRecord[];
  loaded: boolean;
  error: string | null;
  refresh: () => Promise<void>;
}

const ActiveBatchesContext = createContext<ActiveBatchesValue | null>(null);

/**
 * The server is the source of truth for batch status. Mounted once in the console
 * layout, so switching between Scan, Batch, History and Insights never loses a
 * running batch: every page reads the same list, and it is re-fetched from
 * GET /batches on load and every 2 s while anything is still running.
 */
export function ActiveBatchesProvider({ children }: { children: ReactNode }) {
  const [batches, setBatches] = useState<BatchRecord[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const page = await api.listBatches();
      setBatches(page.items);
      setError(null);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not load your batches.",
      );
    } finally {
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const active = useMemo(() => batches.filter((b) => isBatchActive(b)), [batches]);
  usePolling(refresh, BATCH_POLL_MS, active.length > 0);

  const value = useMemo(
    () => ({ batches, active, loaded, error, refresh }),
    [batches, active, loaded, error, refresh],
  );
  return (
    <ActiveBatchesContext.Provider value={value}>
      {children}
    </ActiveBatchesContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useActiveBatches(): ActiveBatchesValue {
  const value = useContext(ActiveBatchesContext);
  if (!value)
    throw new Error(
      "useActiveBatches must be used inside ActiveBatchesProvider",
    );
  return value;
}
