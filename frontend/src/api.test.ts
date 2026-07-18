import assert from "node:assert/strict";
import test from "node:test";

import {
  FrontendApiError,
  fetchTargets,
  requestSessionGrant,
} from "./api.ts";

test("target catalog uses an authenticated same-origin POST and accepts only presentation metadata", async () => {
  let capturedInput: RequestInfo | URL | undefined;
  let capturedInit: RequestInit | undefined;
  const request: typeof fetch = async (input, init) => {
    capturedInput = input;
    capturedInit = init;
    return Response.json({
      targets: [
        { name: "read-only", readOnly: true },
        { name: "shell", readOnly: false },
      ],
    });
  };

  const targets = await fetchTargets(request);

  assert.equal(capturedInput, "/api/targets");
  assert.deepEqual(capturedInit, {
    method: "POST",
    credentials: "same-origin",
  });
  assert.deepEqual(targets, [
    { name: "read-only", readOnly: true },
    { name: "shell", readOnly: false },
  ]);
});

test("target catalog rejects extra authority metadata with a stable non-reflecting error", async () => {
  const hostile = "/bin/attacker --credential=secret";
  const request: typeof fetch = async () =>
    Response.json({
      targets: [{ name: "shell", readOnly: false, executable: hostile }],
    });

  await assert.rejects(fetchTargets(request), (error: unknown) => {
    assert.ok(error instanceof FrontendApiError);
    assert.equal(error.category, "internal-error");
    assert.equal(error.message, "The terminal request could not be completed.");
    assert.ok(!error.message.includes(hostile));
    return true;
  });
});

test("session grant posts only the selected configured target and validates bound metadata", async () => {
  let capturedInput: RequestInfo | URL | undefined;
  let capturedInit: RequestInit | undefined;
  const request: typeof fetch = async (input, init) => {
    capturedInput = input;
    capturedInit = init;
    return Response.json(
      {
        ticket: "opaque-ticket-value",
        target: { name: "shell", readOnly: false },
      },
      { status: 201 },
    );
  };

  const grant = await requestSessionGrant("shell", request);

  assert.equal(capturedInput, "/api/sessions");
  assert.deepEqual(capturedInit, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target: "shell" }),
  });
  assert.deepEqual(grant, {
    ticket: "opaque-ticket-value",
    target: { name: "shell", readOnly: false },
  });
});

test("session grant classifications never expose tickets or hostile response text", async () => {
  const ticket = "opaque-ticket-secret";
  const hostile = `denied because ${ticket}`;
  for (const [status, category] of [
    [401, "denied"],
    [403, "denied"],
    [404, "denied"],
    [408, "timed-out"],
    [504, "timed-out"],
    [500, "internal-error"],
  ] as const) {
    const request: typeof fetch = async () => new Response(hostile, { status });
    await assert.rejects(requestSessionGrant("shell", request), (error: unknown) => {
      assert.ok(error instanceof FrontendApiError);
      assert.equal(error.category, category);
      assert.ok(!error.message.includes(hostile));
      assert.ok(!error.message.includes(ticket));
      return true;
    });
  }
});

test("API response validation fails closed on malformed names tickets and fields", async () => {
  const invalidCatalogs = [
    null,
    {},
    { targets: "shell" },
    { targets: [{ name: "-option", readOnly: false }] },
    { targets: [{ name: "shell", readOnly: "false" }] },
    { targets: [{ name: "shell", readOnly: false, authority: true }] },
  ];
  for (const payload of invalidCatalogs) {
    const request: typeof fetch = async () => Response.json(payload);
    await assert.rejects(fetchTargets(request), FrontendApiError);
  }

  const invalidGrants = [
    null,
    {},
    { ticket: "", target: { name: "shell", readOnly: false } },
    { ticket: "secret", target: { name: "-option", readOnly: false } },
    { ticket: "secret", target: { name: "shell", readOnly: false }, extra: true },
    { ticket: "secret", target: { name: "shell", readOnly: false, argv: [] } },
  ];
  for (const payload of invalidGrants) {
    const request: typeof fetch = async () => Response.json(payload, { status: 201 });
    await assert.rejects(requestSessionGrant("shell", request), FrontendApiError);
  }
});

test("network failures use stable errors rather than thrown messages", async () => {
  const hostile = "network stack leaked a credential";
  const request: typeof fetch = async () => {
    throw new Error(hostile);
  };

  await assert.rejects(fetchTargets(request), (error: unknown) => {
    assert.ok(error instanceof FrontendApiError);
    assert.equal(error.category, "internal-error");
    assert.ok(!error.message.includes(hostile));
    return true;
  });
});
