import assert from "node:assert/strict";
import test from "node:test";

import { IdentityBootstrapError, establishIdentity } from "./identity.ts";

test("development identity bootstrap posts with same-origin credentials", async () => {
  let capturedInput: RequestInfo | URL | undefined;
  let capturedInit: RequestInit | undefined;
  const request: typeof fetch = async (input, init) => {
    capturedInput = input;
    capturedInit = init;
    return new Response(null, { status: 204 });
  };

  await establishIdentity(request);

  assert.equal(capturedInput, "/api/identity");
  assert.deepEqual(capturedInit, {
    method: "POST",
    credentials: "same-origin",
  });
});

test("development identity bootstrap exposes only a stable safe error", async () => {
  const hostile = "attacker-controlled response";
  const request: typeof fetch = async () => new Response(hostile, { status: 503 });

  await assert.rejects(establishIdentity(request), (error: unknown) => {
    assert.ok(error instanceof IdentityBootstrapError);
    assert.equal(error.message, "Development identity is unavailable.");
    assert.ok(!error.message.includes(hostile));
    return true;
  });
});
