import { expect, test, type Page } from "@playwright/test";

import { startTestServer, type TestServer } from "./run-server.ts";

let server: TestServer;

test.beforeAll(async () => {
  server = await startTestServer();
});

test.afterAll(async () => {
  await server.stop();
});

test("real browser connects to a PTY, resizes, pastes, closes, and observes natural exit", async ({
  page,
}) => {
  await page.goto(server.origin);
  await expect(page.getByRole("status")).toHaveText("Ready. Choose a configured target.");
  await expect(page.getByLabel("Configured target")).toHaveValue("interactive");
  expect(new URL(page.url()).search).toBe("");
  expect(new URL(page.url()).hash).toBe("");

  await page.getByRole("button", { name: "Connect terminal" }).click();
  await expect(page.getByRole("status")).toHaveText("Terminal connected.");
  await expectTerminal(page, "READY");

  await page.locator(".xterm-helper-textarea").focus();
  await page.keyboard.type("browser-echo");
  await page.keyboard.press("Enter");
  await expectTerminal(page, "ECHO:browser-echo");

  await page.setViewportSize({ width: 980, height: 620 });
  await page.locator(".xterm-helper-textarea").focus();
  await page.keyboard.type("size");
  await page.keyboard.press("Enter");
  await expectTerminal(page, /RESIZED:\d+ \d+/);
  expect(await terminalText(page)).not.toContain("RESIZED:24 80");

  await paste(page, "paste-æ🙂");
  await page.keyboard.press("Enter");
  await expectTerminal(page, "ECHO:paste-æ🙂");

  await page.getByRole("button", { name: "Close terminal" }).click();
  await expect(page.getByRole("status")).toHaveText("You closed the terminal session.");

  await page.getByRole("button", { name: "Connect terminal" }).click();
  await expect(page.getByRole("status")).toHaveText("Terminal connected.");
  await expectTerminal(page, "READY");
  await page.locator(".xterm-helper-textarea").focus();
  await page.keyboard.type("exit");
  await page.keyboard.press("Enter");
  await expect(page.getByRole("status")).toHaveText("The terminal process exited with code 0.");

  const current = new URL(page.url());
  expect(current.origin).toBe(server.origin);
  expect(current.pathname).toBe("/");
  expect(current.search).toBe("");
  expect(current.hash).toBe("");
  expect(page.url()).not.toMatch(/ticket|credential|secret/i);
});

test("read-only target displays output while suppressing terminal input", async ({ page }) => {
  await page.goto(server.origin);
  await expect(page.getByRole("status")).toHaveText("Ready. Choose a configured target.");
  await page.getByLabel("Configured target").selectOption("read-only");
  await page.getByRole("button", { name: "Connect terminal" }).click();

  await expect(page.getByRole("status")).toHaveText("Terminal connected in read-only mode.");
  await expect(page.getByText("Read-only", { exact: true })).toBeVisible();
  await expectTerminal(page, "READY");
  await page.locator(".xterm-helper-textarea").focus();
  await page.keyboard.type("must-not-echo");
  await page.keyboard.press("Enter");
  await expect.poll(() => terminalText(page)).not.toContain("ECHO:must-not-echo");
  await page.getByRole("button", { name: "Close terminal" }).click();
});

test("authorization rejection is distinct and never reflects the response body", async ({ page }) => {
  const hostile = "credential=attacker-controlled";
  await page.route("**/api/sessions", async (route) => {
    await route.fulfill({
      status: 403,
      contentType: "application/json",
      body: JSON.stringify({
        error: { code: "denied", message: hostile },
      }),
    });
  });
  await page.goto(server.origin);
  await page.getByRole("button", { name: "Connect terminal" }).click();

  await expect(page.getByRole("status")).toHaveText("Terminal access was denied by policy.");
  await expect(page.locator("body")).not.toContainText(hostile);
  expect(page.url()).not.toMatch(/ticket|credential|secret/i);
});

async function terminalText(page: Page): Promise<string> {
  return await page.locator(".xterm-accessibility-tree").textContent() ?? "";
}

async function expectTerminal(page: Page, expected: string | RegExp): Promise<void> {
  await expect.poll(() => terminalText(page)).toMatch(
    typeof expected === "string" ? new RegExp(escapeRegex(expected)) : expected,
  );
}

async function paste(page: Page, text: string): Promise<void> {
  await page.locator(".xterm-helper-textarea").evaluate((element, value) => {
    const transfer = new DataTransfer();
    transfer.setData("text/plain", value);
    element.dispatchEvent(new ClipboardEvent("paste", {
      bubbles: true,
      cancelable: true,
      clipboardData: transfer,
    }));
  }, text);
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
