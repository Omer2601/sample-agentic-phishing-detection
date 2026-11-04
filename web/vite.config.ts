// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

// Static SPA. Output goes to dist/ and is served as static assets behind
// CloudFront (see web/DESIGN.md "Build and deploy" section). No SSR.

// Bind the dev server to loopback by default. The signing proxy (sign_proxy.py)
// holds live AWS credentials and performs no authentication of its own, so it is
// deliberately loopback-only; a dev server bound to 0.0.0.0 would re-expose that
// proxy (and the arbitrary-file-read surface of the March 2025 Vite advisories,
// CVE-2025-30208 and follow-ups) to the local network, defeating that design.
// Container/remote use that genuinely needs a non-loopback bind must opt in
// explicitly, e.g. VITE_DEV_HOST=0.0.0.0, and is expected to run behind its own
// network controls.
const devHost = process.env.VITE_DEV_HOST ?? "127.0.0.1";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    host: devHost,
    // Same-origin /api in development. The local signing proxy holds the AWS
    // credentials and re-signs to API Gateway, mirroring what the production
    // web Lambda does with its execution role, so the browser never signs and
    // never learns the private API endpoint. Start it with: npm run devproxy
    proxy: {
      // Regex, not the "/api" prefix string: a bare prefix also swallows sibling
      // routes such as /api-console, which are SPA pages and must reach the
      // history fallback. This mirrors the production web tier, which forwards
      // only when the path is exactly /api or starts with /api/ (see
      // web/server/wsgi.py).
      "^/api(/|$)": {
        target: process.env.VITE_DEV_PROXY ?? "http://127.0.0.1:8787",
        changeOrigin: false,
        // Scans are asynchronous and polled, but a slow upstream should surface
        // as a proxy error, not a silently aborted request.
        timeout: 180000,
        proxyTimeout: 180000,
      },
      // Registration routes are mounted under /auth, not /api. Without this rule
      // a dev-mode POST /auth/register falls through to the SPA history fallback
      // and returns index.html with status 200, which reads as a successful
      // registration that never happened.
      "^/auth/(register|config)$": {
        target: process.env.VITE_DEV_PROXY ?? "http://127.0.0.1:8787",
        changeOrigin: false,
      },
    },
  },
  build: {
    outDir: "dist",
    // No source maps in the published bundle. Source maps ship the readable
    // pre-minification source (and inline it into .map files served from the
    // CDN), handing an attacker the original code and structure. If a monitoring
    // workflow ever needs them, set this to "hidden" so maps are generated for
    // upload to the error tracker but not referenced from or served with the
    // bundle. Default here is off.
    sourcemap: false,
    // Split the charting lib out so the initial bundle stays lean.
    rollupOptions: {
      output: {
        manualChunks: {
          recharts: ["recharts"],
        },
      },
    },
  },
});
