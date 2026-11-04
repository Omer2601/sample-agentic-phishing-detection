// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { defineConfig } from "vitest/config";
import path from "node:path";

// Pure logic tests (*.test.ts) run in Node, which is faster and keeps them honest
// about not touching the DOM. Component tests (*.test.tsx) run in jsdom.
// Vitest 4 removed environmentMatchGlobs, so the split is two projects.
const alias = { "@": path.resolve(__dirname, "./src") };
const shared = {
  setupFiles: ["src/test/setup.ts"],
  globals: false,
};

export default defineConfig({
  resolve: { alias },
  test: {
    projects: [
      {
        resolve: { alias },
        test: {
          ...shared,
          name: "node",
          environment: "node",
          include: ["src/**/*.test.ts"],
        },
      },
      {
        resolve: { alias },
        test: {
          ...shared,
          name: "dom",
          environment: "jsdom",
          include: ["src/**/*.test.tsx"],
        },
      },
    ],
  },
});
