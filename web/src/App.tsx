// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useEffect } from "react";
import { Navigate, Outlet, Route, Routes, useLocation } from "react-router-dom";
import { AppShell } from "@/components/AppShell";
import { ActiveBatchesProvider } from "@/hooks/useActiveBatches";
import { ScanPage } from "@/pages/ScanPage";
import { BatchPage } from "@/pages/BatchPage";
import { BatchDetailPage } from "@/pages/BatchDetailPage";
import { ResultPage } from "@/pages/ResultPage";
import { HistoryPage } from "@/pages/HistoryPage";
import { InsightsPage } from "@/pages/InsightsPage";
import { ApiConsolePage } from "@/pages/ApiConsolePage";
import { RegisterPage } from "@/pages/RegisterPage";
import { WelcomePage } from "@/pages/WelcomePage";

/**
 * The signed-in console. The provider lives here, above every page, so batch
 * status is shared and survives navigation. Keying the content on the path
 * replays the same fade-in used by result cards, which gives Scan, Batch,
 * History and Insights one consistent page transition.
 */
function ConsoleLayout() {
  const { pathname } = useLocation();
  return (
    <ActiveBatchesProvider>
      <AppShell>
        <div key={pathname} className="animate-fade-in">
          <Outlet />
        </div>
      </AppShell>
    </ActiveBatchesProvider>
  );
}

/** Sign-in is a server route that redirects to Cognito managed login. */
function SignInRedirect() {
  useEffect(() => {
    window.location.assign("/auth/login");
  }, []);
  return null;
}

export default function App() {
  return (
    <Routes>
      <Route path="/welcome" element={<WelcomePage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/login" element={<SignInRedirect />} />

      <Route element={<ConsoleLayout />}>
        <Route path="/" element={<ScanPage />} />
        <Route path="/scan" element={<Navigate to="/" replace />} />
        <Route path="/results/:scanId" element={<ResultPage />} />
        <Route path="/batch" element={<BatchPage />} />
        <Route path="/batch/:batchId" element={<BatchDetailPage />} />
        <Route path="/history" element={<HistoryPage />} />
        <Route path="/insights" element={<InsightsPage />} />
        <Route path="/api-console" element={<ApiConsolePage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
