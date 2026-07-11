import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  MAX_BINARY_BYTES,
  MAX_CONTROL_BYTES,
  PROTOCOL_VERSION,
  ProtocolCodecError,
  decodeClientBinary,
  decodeClientControl,
  decodeServerBinary,
  decodeServerControl,
  encodeClientControl,
  encodeServerControl,
} from "./protocol.ts";

interface ValidFixture {
  name: string;
  direction: "client" | "server";
  wire: string;
}

interface InvalidFixture extends ValidFixture {
  error: string;
}

interface Fixtures {
  protocolVersion: number;
  maxControlBytes: number;
  maxBinaryBytes: number;
  valid: ValidFixture[];
  invalid: InvalidFixture[];
}

const fixtures = JSON.parse(
  readFileSync(new URL("../../protocol/fixtures.json", import.meta.url), "utf8"),
) as Fixtures;

function expectCodecError(action: () => unknown, code: string, hostile?: string): void {
  assert.throws(action, (error: unknown) => {
    assert.ok(error instanceof ProtocolCodecError);
    assert.equal(error.code, code);
    if (hostile !== undefined) assert.ok(!error.message.includes(hostile));
    return true;
  });
}

test("shared constants match", () => {
  assert.equal(PROTOCOL_VERSION, fixtures.protocolVersion);
  assert.equal(MAX_CONTROL_BYTES, fixtures.maxControlBytes);
  assert.equal(MAX_BINARY_BYTES, fixtures.maxBinaryBytes);
});

test("valid shared fixtures round trip exactly", () => {
  for (const fixture of fixtures.valid) {
    const encoded = fixture.direction === "client"
      ? encodeClientControl(decodeClientControl(fixture.wire))
      : encodeServerControl(decodeServerControl(fixture.wire));
    assert.equal(encoded, fixture.wire, fixture.name);
  }
});

test("invalid shared fixtures have stable safe errors", () => {
  for (const fixture of fixtures.invalid) {
    expectCodecError(
      () => fixture.direction === "client"
        ? decodeClientControl(fixture.wire)
        : decodeServerControl(fixture.wire),
      fixture.error,
      fixture.wire,
    );
  }
});

test("binary frames accept empty and maximum but reject oversize", () => {
  assert.deepEqual(decodeClientBinary(new Uint8Array()), { type: "terminal-input", data: new Uint8Array() });
  const maximum = new Uint8Array(MAX_BINARY_BYTES).fill(7);
  assert.deepEqual(decodeServerBinary(maximum), { type: "terminal-output", data: maximum });
  expectCodecError(() => decodeClientBinary(new Uint8Array(MAX_BINARY_BYTES + 1)), "binary-too-large");
});

test("text bound is measured in UTF-8 bytes before JSON parsing", () => {
  const multibyte = `{"version":1,"type":"close","padding":"${"💥".repeat(MAX_CONTROL_BYTES)}"}`;
  expectCodecError(() => decodeClientControl(multibyte), "control-too-large");

  const prefix = '{"version":1,"type":"close","padding":"';
  const suffix = '"}';
  const maximum = prefix + "a".repeat(MAX_CONTROL_BYTES - prefix.length - suffix.length) + suffix;
  assert.equal(maximum.length, MAX_CONTROL_BYTES);
  expectCodecError(() => decodeClientControl(maximum), "unknown-field");
});

test("encoders reject invalid caller-constructed values", () => {
  expectCodecError(
    () => encodeClientControl({ type: "resize", cols: 0, rows: 24 }),
    "invalid-field",
  );
  expectCodecError(
    () => encodeServerControl({
      type: "error",
      code: "Bad_Code",
      message: "safe",
    }),
    "invalid-field",
  );
  expectCodecError(
    () => encodeServerControl({ type: "error", code: "a".repeat(65), message: "safe" }),
    "invalid-field",
  );
  expectCodecError(
    () => encodeServerControl({ type: "error", code: "safe-code", message: "a".repeat(257) }),
    "invalid-field",
  );
  expectCodecError(
    () => encodeServerControl({ type: "error", code: "safe-code", message: "\ud800" }),
    "invalid-field",
  );
});
