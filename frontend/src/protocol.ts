export const PROTOCOL_VERSION = 1 as const;
export const MAX_CONTROL_BYTES = 4_096;
export const MAX_BINARY_BYTES = 65_536;
export const MAX_DIMENSION = 4_096;

export type ClientControl =
  | { type: "resize"; cols: number; rows: number }
  | { type: "close" };

export type ExitStatus =
  | { kind: "code"; code: number }
  | { kind: "signal"; signal: number }
  | { kind: "unavailable" };

export type CloseReason =
  | "client-request"
  | "exited"
  | "timeout"
  | "policy"
  | "protocol-error"
  | "transport-error"
  | "internal-error";

export type ServerControl =
  | { type: "exit-status"; status: ExitStatus }
  | { type: "error"; code: string; message: string }
  | { type: "close"; reason: CloseReason };

export interface ClientBinaryFrame {
  type: "terminal-input";
  data: Uint8Array;
}

export interface ServerBinaryFrame {
  type: "terminal-output";
  data: Uint8Array;
}

export type ProtocolErrorCode =
  | "binary-too-large"
  | "control-too-large"
  | "malformed-control"
  | "invalid-control"
  | "duplicate-field"
  | "missing-field"
  | "unknown-field"
  | "unknown-message-type"
  | "unsupported-version"
  | "invalid-direction"
  | "invalid-field";

export class ProtocolCodecError extends Error {
  readonly code: ProtocolErrorCode;

  constructor(code: ProtocolErrorCode) {
    super(code);
    this.name = "ProtocolCodecError";
    this.code = code;
  }
}

export function decodeClientBinary(data: Uint8Array): ClientBinaryFrame {
  checkBinaryLength(data);
  return { type: "terminal-input", data: new Uint8Array(data) };
}

export function decodeServerBinary(data: Uint8Array): ServerBinaryFrame {
  checkBinaryLength(data);
  return { type: "terminal-output", data: new Uint8Array(data) };
}

export function decodeClientControl(text: string): ClientControl {
  const value = parseControl(text);
  const type = header(value);
  switch (type) {
    case "resize":
      exactKeys(value, ["version", "type", "cols", "rows"]);
      return {
        type: "resize",
        cols: dimension(value, "cols"),
        rows: dimension(value, "rows"),
      };
    case "close":
      exactKeys(value, ["version", "type"]);
      return { type: "close" };
    case "exit-status":
    case "error":
      throw new ProtocolCodecError("invalid-direction");
    default:
      throw new ProtocolCodecError("unknown-message-type");
  }
}

export function decodeServerControl(text: string): ServerControl {
  const value = parseControl(text);
  const type = header(value);
  switch (type) {
    case "exit-status":
      exactKeys(value, ["version", "type", "status"]);
      return { type: "exit-status", status: parseExitStatus(field(value, "status")) };
    case "error": {
      exactKeys(value, ["version", "type", "code", "message"]);
      const code = stringField(value, "code");
      const message = stringField(value, "message");
      validateError(code, message);
      return { type: "error", code, message };
    }
    case "close": {
      exactKeys(value, ["version", "type", "reason"]);
      const reason = stringField(value, "reason");
      if (!isCloseReason(reason)) throw new ProtocolCodecError("invalid-field");
      return { type: "close", reason };
    }
    case "resize":
      throw new ProtocolCodecError("invalid-direction");
    default:
      throw new ProtocolCodecError("unknown-message-type");
  }
}

export function encodeClientControl(message: ClientControl): string {
  switch (message.type) {
    case "resize": {
      const cols = checkedDimension(message.cols);
      const rows = checkedDimension(message.rows);
      return checkedStringify({ version: PROTOCOL_VERSION, type: "resize", cols, rows });
    }
    case "close":
      return checkedStringify({ version: PROTOCOL_VERSION, type: "close" });
  }
}

export function encodeServerControl(message: ServerControl): string {
  switch (message.type) {
    case "exit-status":
      validateExitStatus(message.status);
      return checkedStringify({ version: PROTOCOL_VERSION, type: "exit-status", status: message.status });
    case "error":
      validateError(message.code, message.message);
      return checkedStringify({
        version: PROTOCOL_VERSION,
        type: "error",
        code: message.code,
        message: message.message,
      });
    case "close":
      if (!isCloseReason(message.reason)) throw new ProtocolCodecError("invalid-field");
      return checkedStringify({ version: PROTOCOL_VERSION, type: "close", reason: message.reason });
  }
}

function checkBinaryLength(data: Uint8Array): void {
  if (data.byteLength > MAX_BINARY_BYTES) throw new ProtocolCodecError("binary-too-large");
}

function parseControl(text: string): Record<string, unknown> {
  if (new TextEncoder().encode(text).byteLength > MAX_CONTROL_BYTES) {
    throw new ProtocolCodecError("control-too-large");
  }
  detectDuplicateKeys(text);
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw new ProtocolCodecError("malformed-control");
  }
  if (!isRecord(value)) throw new ProtocolCodecError("invalid-control");
  return value;
}

function header(value: Record<string, unknown>): string {
  const version = field(value, "version");
  if (!Number.isInteger(version)) throw new ProtocolCodecError("invalid-field");
  if (version !== PROTOCOL_VERSION) throw new ProtocolCodecError("unsupported-version");
  return stringField(value, "type");
}

function field(value: Record<string, unknown>, key: string): unknown {
  if (!Object.hasOwn(value, key)) throw new ProtocolCodecError("missing-field");
  return value[key];
}

function stringField(value: Record<string, unknown>, key: string): string {
  const result = field(value, key);
  if (typeof result !== "string") throw new ProtocolCodecError("invalid-field");
  return result;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): void {
  if (expected.some((key) => !Object.hasOwn(value, key))) {
    throw new ProtocolCodecError("missing-field");
  }
  if (Object.keys(value).some((key) => !expected.includes(key))) {
    throw new ProtocolCodecError("unknown-field");
  }
}

function dimension(value: Record<string, unknown>, key: string): number {
  return checkedDimension(field(value, key));
}

function checkedDimension(value: unknown): number {
  if (!Number.isInteger(value) || typeof value !== "number" || value < 1 || value > MAX_DIMENSION) {
    throw new ProtocolCodecError("invalid-field");
  }
  return value;
}

function parseExitStatus(value: unknown): ExitStatus {
  if (!isRecord(value)) throw new ProtocolCodecError("invalid-field");
  const kind = stringField(value, "kind");
  switch (kind) {
    case "code": {
      exactKeys(value, ["kind", "code"]);
      const code = field(value, "code");
      if (!Number.isInteger(code) || typeof code !== "number" || code < 0 || code > 255) {
        throw new ProtocolCodecError("invalid-field");
      }
      return { kind, code };
    }
    case "signal": {
      exactKeys(value, ["kind", "signal"]);
      const signal = field(value, "signal");
      if (!Number.isInteger(signal) || typeof signal !== "number" || signal < 1 || signal > 127) {
        throw new ProtocolCodecError("invalid-field");
      }
      return { kind, signal };
    }
    case "unavailable":
      exactKeys(value, ["kind"]);
      return { kind };
    default:
      throw new ProtocolCodecError("invalid-field");
  }
}

function validateExitStatus(status: ExitStatus): void {
  parseExitStatus(status);
}

function validateError(code: string, message: string): void {
  if (!/^[a-z](?:[a-z0-9]|-(?!-))*$/.test(code) || code.length > 64) {
    throw new ProtocolCodecError("invalid-field");
  }
  const characters = [...message];
  if (characters.length < 1 || characters.length > 256 || characters.some(isAsciiControl)) {
    throw new ProtocolCodecError("invalid-field");
  }
}

function isAsciiControl(character: string): boolean {
  const code = character.codePointAt(0) ?? 0;
  return code <= 0x1f || code === 0x7f;
}

function isCloseReason(reason: string): reason is CloseReason {
  return [
    "client-request",
    "exited",
    "timeout",
    "policy",
    "protocol-error",
    "transport-error",
    "internal-error",
  ].includes(reason);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function checkedStringify(value: unknown): string {
  const result = JSON.stringify(value);
  if (new TextEncoder().encode(result).byteLength > MAX_CONTROL_BYTES) {
    throw new ProtocolCodecError("control-too-large");
  }
  return result;
}

function detectDuplicateKeys(text: string): void {
  const objectKeys: Array<Set<string> | null> = [];
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (character === "{") {
      objectKeys.push(new Set());
    } else if (character === "[") {
      objectKeys.push(null);
    } else if (character === "}" || character === "]") {
      objectKeys.pop();
    } else if (character === '"') {
      const start = index;
      index += 1;
      while (index < text.length) {
        if (text[index] === "\\") {
          index += 2;
          continue;
        }
        if (text[index] === '"') break;
        index += 1;
      }
      if (index >= text.length) return;
      let next = index + 1;
      while (/\s/.test(text[next] ?? "")) next += 1;
      const keys = objectKeys.at(-1);
      if (text[next] === ":" && keys instanceof Set) {
        let key: string;
        try {
          key = JSON.parse(text.slice(start, index + 1)) as string;
        } catch {
          return;
        }
        if (keys.has(key)) throw new ProtocolCodecError("duplicate-field");
        keys.add(key);
      }
    }
  }
}
