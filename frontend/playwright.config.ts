import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 30_000,
  expect: {
    timeout: 8_000,
  },
  use: {
    browserName: "chromium",
    headless: true,
    viewport: { width: 1_280, height: 800 },
  },
});
