import assert from "node:assert/strict";
import test from "node:test";

import {
  FIXTURE_AUTHORIZATION,
  FIXTURE_IDENTITY,
  authorize,
} from "./reverse-proxy-auth.mjs";
import {
  canonicalCookie,
  decodeServerFrames,
  maskedFrame,
  scanAuditText,
  validatedTicket,
} from "./reverse-proxy-session.mjs";

test("synthetic auth denies missing invalid duplicate and oversized authorization", () => {
  for (const authorization of [
    undefined,
    "Bearer wrong-fixture-value",
    [FIXTURE_AUTHORIZATION, FIXTURE_AUTHORIZATION],
    `Bearer ${"x".repeat(4096)}`,
  ]) {
    assert.deepEqual(authorize("GET", "/verify", authorization), {
      status: 401,
      identity: undefined,
    });
  }
});

test("synthetic auth returns one bounded canonical identity only for its fixed grant", () => {
  assert.deepEqual(authorize("GET", "/verify", FIXTURE_AUTHORIZATION), {
    status: 204,
    identity: FIXTURE_IDENTITY,
  });
  assert.deepEqual(authorize("POST", "/verify", FIXTURE_AUTHORIZATION), {
    status: 405,
    identity: undefined,
  });
  assert.deepEqual(authorize("GET", "/other", FIXTURE_AUTHORIZATION), {
    status: 404,
    identity: undefined,
  });
});

test("client fixture extracts only a canonical secure ttygate cookie", () => {
  const cookie = canonicalCookie([
    "ttgate_session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; Secure; HttpOnly; SameSite=Strict; Path=/",
  ]);
  assert.equal(
    cookie,
    "ttgate_session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  );
  for (const invalid of [
    undefined,
    [],
    ["other=value; Secure; HttpOnly; SameSite=Strict; Path=/"],
    ["ttgate_session=value; HttpOnly; SameSite=Strict; Path=/"],
    [
      "ttgate_session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; Secure; HttpOnly; SameSite=Strict; Path=/",
      "ttgate_session=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB; Secure; HttpOnly; SameSite=Strict; Path=/",
    ],
  ]) {
    assert.throws(() => canonicalCookie(invalid), /identity cookie invalid/);
  }
});

test("client fixture accepts only a bounded opaque ticket response", () => {
  assert.equal(
    validatedTicket(
      201,
      '{"ticket":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","target":{"name":"maintenance-shell","readOnly":false}}',
    ),
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  );
  for (const [status, body] of [
    [
      200,
      '{"ticket":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","target":{"name":"maintenance-shell","readOnly":false}}',
    ],
    [201, "{}"],
    [201, '{"ticket":"short"}'],
    [201, `{"ticket":"${"A".repeat(44)}"}`],
    [
      201,
      '{"ticket":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","target":{"name":"other","readOnly":false}}',
    ],
    [201, "not-json"],
  ]) {
    assert.throws(() => validatedTicket(status, body), /session grant invalid/);
  }
});

test("masked client frames and bounded server frame decoding preserve payload bytes", () => {
  const frame = maskedFrame(0x2, Buffer.from("fixture-input"));
  assert.equal(frame[0], 0x82);
  assert.equal(frame[1] & 0x80, 0x80);

  const serverFrame = Buffer.concat([
    Buffer.from([0x82, 0x0e]),
    Buffer.from("fixture-output"),
  ]);
  assert.deepEqual(decodeServerFrames(serverFrame), {
    frames: [{ opcode: 0x2, payload: Buffer.from("fixture-output") }],
    remaining: Buffer.alloc(0),
  });
  assert.throws(
    () => decodeServerFrames(Buffer.from([0x82, 0x7f])),
    /server frame invalid/,
  );
});

test("complete audit scan requires the canonical lifecycle and rejects secret classes", () => {
  const good = [
    '{"schema_version":1,"event_type":"authentication-succeeded","identity":"synthetic-user","remote_address":"192.0.2.10:40000","authenticated_at":"2026-07-19T00:00:00Z"}',
    '{"schema_version":1,"event_type":"session-started","session_id":"synthetic-correlation","identity":"synthetic-user","target":"maintenance-shell","remote_address":"192.0.2.10:40001","started_at":"2026-07-19T00:00:01Z"}',
    '{"schema_version":1,"event_type":"session-ended","session_id":"synthetic-correlation","identity":"synthetic-user","target":"maintenance-shell","remote_address":"192.0.2.10:40001","started_at":"2026-07-19T00:00:01Z","ended_at":"2026-07-19T00:00:02Z","outcome":{"kind":"client-request"}}',
  ].join("\n") + "\n";
  assert.equal(scanAuditText(good), 3);

  for (const forbidden of [
    "Authorization",
    "chunk42-fixture-only",
    "ttgate_session=",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "TTYGATE_PROXY_FLOW_OK",
    "printf",
    "BEGIN PRIVATE KEY",
  ]) {
    assert.throws(
      () => scanAuditText(`${good}${forbidden}\n`),
      /audit content invalid/,
    );
  }
  const withRuntimeSecret =
    `${good}{"schema_version":1,"event_type":"access-denied","reason":"runtime-only-secret"}\n`;
  assert.throws(
    () => scanAuditText(withRuntimeSecret, ["runtime-only-secret"]),
    /audit content invalid/,
  );
});
