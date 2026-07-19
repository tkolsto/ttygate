import { createHash, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { request } from "node:https";
import { connect } from "node:tls";
import { pathToFileURL } from "node:url";

import {
  FIXTURE_AUTHORIZATION,
  FIXTURE_IDENTITY,
} from "./reverse-proxy-auth.mjs";

const ORIGIN = "https://terminal.example.invalid:8443";
const HOSTNAME = "terminal.example.invalid";
const PORT = 8443;
const TARGET = "maintenance-shell";
const TERMINAL_SENTINEL = "TTYGATE_PROXY_FLOW_OK";

export function canonicalCookie(setCookie) {
  if (!Array.isArray(setCookie) || setCookie.length !== 1) {
    throw new Error("identity cookie invalid");
  }
  const value = setCookie[0];
  const lower = value.toLowerCase();
  if (
    !/^ttgate_session=[A-Za-z0-9_-]{43};/.test(value) ||
    !lower.includes("; secure") ||
    !lower.includes("; httponly") ||
    !lower.includes("; samesite=strict") ||
    !lower.includes("; path=/")
  ) {
    throw new Error("identity cookie invalid");
  }
  return value.split(";", 1)[0];
}

export function validatedTicket(status, body) {
  if (status !== 201 || Buffer.byteLength(body) > 2048) {
    throw new Error("session grant invalid");
  }
  let value;
  try {
    value = JSON.parse(body);
  } catch {
    throw new Error("session grant invalid");
  }
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !== "target,ticket" ||
    typeof value.ticket !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(value.ticket) ||
    value.target === null ||
    typeof value.target !== "object" ||
    Array.isArray(value.target) ||
    Object.keys(value.target).sort().join(",") !== "name,readOnly" ||
    value.target.name !== TARGET ||
    value.target.readOnly !== false
  ) {
    throw new Error("session grant invalid");
  }
  return value.ticket;
}

export function maskedFrame(opcode, value) {
  const payload = Buffer.from(value);
  if (payload.length > 65_536) throw new Error("client frame invalid");
  const mask = randomBytes(4);
  const lengthBytes = payload.length < 126 ? 0 : 2;
  const frame = Buffer.alloc(2 + lengthBytes + mask.length + payload.length);
  frame[0] = 0x80 | opcode;
  if (lengthBytes === 0) {
    frame[1] = 0x80 | payload.length;
  } else {
    frame[1] = 0x80 | 126;
    frame.writeUInt16BE(payload.length, 2);
  }
  const maskOffset = 2 + lengthBytes;
  mask.copy(frame, maskOffset);
  for (let index = 0; index < payload.length; index += 1) {
    frame[maskOffset + 4 + index] = payload[index] ^ mask[index % 4];
  }
  return frame;
}

export function decodeServerFrames(buffer) {
  const frames = [];
  let offset = 0;
  while (buffer.length - offset >= 2) {
    const first = buffer[offset];
    const second = buffer[offset + 1];
    if ((first & 0x70) !== 0 || (second & 0x80) !== 0) {
      throw new Error("server frame invalid");
    }
    let length = second & 0x7f;
    let headerLength = 2;
    if (length === 126) {
      if (buffer.length - offset < 4) break;
      length = buffer.readUInt16BE(offset + 2);
      headerLength = 4;
    } else if (length === 127) {
      throw new Error("server frame invalid");
    }
    if (length > 65_536) throw new Error("server frame invalid");
    if (buffer.length - offset < headerLength + length) break;
    frames.push({
      opcode: first & 0x0f,
      payload: buffer.subarray(
        offset + headerLength,
        offset + headerLength + length,
      ),
    });
    offset += headerLength + length;
  }
  return { frames, remaining: buffer.subarray(offset) };
}

export function validWebSocketHandshake(head, key) {
  if (typeof head !== "string" || typeof key !== "string") return false;
  const lines = head.split("\r\n");
  if (!/^HTTP\/1\.1 101(?: |$)/.test(lines.shift() ?? "")) return false;
  const headers = new Map();
  for (const line of lines) {
    const separator = line.indexOf(":");
    if (separator <= 0) return false;
    const name = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (headers.has(name)) return false;
    headers.set(name, value);
  }
  const expected = createHash("sha1")
    .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`, "ascii")
    .digest("base64");
  return (
    headers.get("upgrade")?.toLowerCase() === "websocket" &&
    (headers.get("connection") ?? "")
      .split(",")
      .some((value) => value.trim().toLowerCase() === "upgrade") &&
    headers.get("sec-websocket-accept") === expected
  );
}

export function scanAuditText(text, runtimeSecrets = []) {
  if (
    typeof text !== "string" ||
    text.length === 0 ||
    Buffer.byteLength(text) > 1_048_576 ||
    !text.endsWith("\n")
  ) {
    throw new Error("audit content invalid");
  }
  const lower = text.toLowerCase();
  for (const forbidden of [
    "authorization",
    "chunk42-fixture-only",
    "ttgate_session=",
    "ttgate_proxy_flow_ok",
    "printf",
    "begin private key",
    '"ticket"',
    '"cookie"',
    '"headers"',
    '"terminal_input"',
    '"terminal_output"',
    '"command"',
    '"arguments"',
    '"environment"',
    '"private_key"',
    ...runtimeSecrets.map((value) => value.toLowerCase()),
  ]) {
    if (forbidden !== "" && lower.includes(forbidden)) {
      throw new Error("audit content invalid");
    }
  }
  const values = text.trimEnd().split("\n").map((line) => {
    try {
      return JSON.parse(line);
    } catch {
      throw new Error("audit content invalid");
    }
  });
  const lifecycle = values.filter((value) =>
    ["authentication-succeeded", "session-started", "session-ended"].includes(
      value.event_type,
    )
  );
  const starts = new Map();
  const ends = new Map();
  for (const value of lifecycle) {
    if (
      value.event_type !== "session-started" &&
      value.event_type !== "session-ended"
    ) {
      continue;
    }
    if (
      typeof value.session_id !== "string" ||
      value.session_id.length === 0 ||
      value.session_id.length > 128 ||
      value.identity !== FIXTURE_IDENTITY ||
      value.target !== TARGET
    ) {
      throw new Error("audit content invalid");
    }
    const records = value.event_type === "session-started" ? starts : ends;
    if (records.has(value.session_id)) throw new Error("audit content invalid");
    records.set(value.session_id, value);
  }
  if (
    !lifecycle.some((value) =>
      value.event_type === "authentication-succeeded" &&
      value.identity === FIXTURE_IDENTITY
    ) ||
    starts.size === 0 ||
    starts.size !== ends.size ||
    [...starts.keys()].some((sessionId) => !ends.has(sessionId)) ||
    lifecycle.some((value) =>
      typeof value.remote_address === "string" &&
      !value.remote_address.startsWith("192.0.2.10:")
    )
  ) {
    throw new Error("audit content invalid");
  }
  return values.length;
}

function httpsRequest(ca, method, path, headers = {}, body = "") {
  return new Promise((resolve, reject) => {
    const outgoing = request(
      {
        ca,
        hostname: HOSTNAME,
        port: PORT,
        method,
        path,
        servername: HOSTNAME,
        headers: {
          ...headers,
          "Content-Length": Buffer.byteLength(body),
        },
        timeout: 5_000,
      },
      (response) => {
        const chunks = [];
        let size = 0;
        response.on("data", (chunk) => {
          size += chunk.length;
          if (size > 1_048_576) {
            response.destroy(new Error("HTTPS response exceeded fixture bound"));
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () => {
          resolve({
            status: response.statusCode,
            headers: response.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    );
    outgoing.once("timeout", () => {
      outgoing.destroy(new Error("HTTPS request timed out"));
    });
    outgoing.once("error", reject);
    outgoing.end(body);
  });
}

function openWebSocket(ca, cookie, ticket, hold = false) {
  return new Promise((resolve, reject) => {
    const socket = connect({
      ca,
      host: HOSTNAME,
      port: PORT,
      servername: HOSTNAME,
      rejectUnauthorized: true,
    });
    let handshake = Buffer.alloc(0);
    let frames = Buffer.alloc(0);
    let output = Buffer.alloc(0);
    let upgraded = false;
    let lifecycleReady = false;
    let closeRequested = false;
    let settled = false;
    let websocketKey;
    const timeout = setTimeout(() => {
      socket.destroy(new Error("WebSocket lifecycle timed out"));
    }, 10_000);

    const fail = (error) => {
      if (settled) return;
      clearTimeout(timeout);
      settled = true;
      reject(error instanceof Error ? error : new Error("WebSocket failed"));
    };
    const finish = () => {
      if (settled) return;
      clearTimeout(timeout);
      settled = true;
      resolve();
    };
    socket.once("error", (error) => {
      if (hold && lifecycleReady) {
        finish();
      } else {
        fail(error);
      }
    });
    socket.once("close", () => {
      if (hold && lifecycleReady) {
        finish();
      } else if (!settled) {
        fail(new Error("WebSocket closed before lifecycle completion"));
      }
    });
    socket.once("secureConnect", () => {
      websocketKey = randomBytes(16).toString("base64");
      socket.write(
        "GET /api/ws HTTP/1.1\r\n" +
          `Host: ${HOSTNAME}:${PORT}\r\n` +
          "Upgrade: websocket\r\n" +
          "Connection: Upgrade\r\n" +
          `Sec-WebSocket-Key: ${websocketKey}\r\n` +
          "Sec-WebSocket-Version: 13\r\n" +
          `Origin: ${ORIGIN}\r\n` +
          `Authorization: ${FIXTURE_AUTHORIZATION}\r\n` +
          `Cookie: ${cookie}\r\n\r\n`,
      );
    });
    socket.on("data", (chunk) => {
      if (!upgraded) {
        handshake = Buffer.concat([handshake, chunk]);
        if (handshake.length > 16_384) {
          socket.destroy(new Error("WebSocket handshake exceeded fixture bound"));
          return;
        }
        const boundary = handshake.indexOf("\r\n\r\n");
        if (boundary === -1) return;
        const head = handshake.subarray(0, boundary).toString("ascii");
        if (!validWebSocketHandshake(head, websocketKey)) {
          socket.destroy(new Error("WebSocket upgrade was rejected"));
          return;
        }
        upgraded = true;
        frames = handshake.subarray(boundary + 4);
        handshake = Buffer.alloc(0);
        socket.write(maskedFrame(0x1, JSON.stringify({ ticket })));
        socket.write(
          maskedFrame(
            0x2,
            Buffer.from(`printf '${TERMINAL_SENTINEL}\\n'\n`, "utf8"),
          ),
        );
      } else {
        frames = Buffer.concat([frames, chunk]);
      }

      const decoded = decodeServerFrames(frames);
      frames = Buffer.from(decoded.remaining);
      for (const frame of decoded.frames) {
        if (frame.opcode === 0x2) {
          output = Buffer.concat([output, frame.payload]);
          if (output.length > 262_144) {
            socket.destroy(new Error("terminal output exceeded fixture bound"));
            return;
          }
          if (
            output.includes(Buffer.from(TERMINAL_SENTINEL)) &&
            !lifecycleReady
          ) {
            lifecycleReady = true;
            if (hold) {
              clearTimeout(timeout);
              process.stdout.write("REVERSE_PROXY_SESSION_HOLD_READY\n");
              continue;
            }
          }
          if (!hold && lifecycleReady && !closeRequested) {
            closeRequested = true;
            socket.write(
              maskedFrame(
                0x1,
                JSON.stringify({ version: 1, type: "close" }),
              ),
            );
          }
        } else if (frame.opcode === 0x1) {
          let control;
          try {
            control = JSON.parse(frame.payload.toString("utf8"));
          } catch {
            socket.destroy(new Error("server control frame invalid"));
            return;
          }
          if (control.type === "close" && output.includes(TERMINAL_SENTINEL)) {
            socket.end(maskedFrame(0x8, Buffer.alloc(0)));
            finish();
          }
        } else if (frame.opcode === 0x8) {
          if (!output.includes(TERMINAL_SENTINEL)) {
            socket.destroy(new Error("WebSocket closed before PTY output"));
          }
        }
      }
    });
  });
}

export async function runLifecycle(certificatePath, secretPath) {
  const ca = readFileSync(certificatePath);
  const missing = await httpsRequest(ca, "GET", "/");
  if (![401, 403].includes(missing.status)) {
    throw new Error("missing authentication was not denied");
  }

  const common = {
    Authorization: FIXTURE_AUTHORIZATION,
    Origin: ORIGIN,
  };
  const health = await httpsRequest(ca, "GET", "/healthz", common);
  if (health.status !== 200 || health.body !== "ok\n") {
    throw new Error(
      `proxied health check failed: status=${health.status} body=${JSON.stringify(health.body.slice(0, 128))}`,
    );
  }
  const frontend = await httpsRequest(ca, "GET", "/", common);
  if (
    frontend.status !== 200 ||
    !frontend.body.toLowerCase().includes("<title>ttygate</title>")
  ) {
    throw new Error("proxied frontend failed");
  }

  const identity = await httpsRequest(
    ca,
    "POST",
    "/api/identity",
    {
      ...common,
      "X-Authenticated-User": ["spoofed-user", "second-spoofed-user"],
    },
  );
  if (identity.status !== 204) {
    throw new Error(
      `identity establishment failed: status=${identity.status} body=${JSON.stringify(identity.body.slice(0, 128))}`,
    );
  }
  const cookie = canonicalCookie(identity.headers["set-cookie"]);
  const payload = JSON.stringify({ target: TARGET });
  const grant = await httpsRequest(
    ca,
    "POST",
    "/api/sessions",
    {
      ...common,
      Cookie: cookie,
      "Content-Type": "application/json",
    },
    payload,
  );
  const ticket = validatedTicket(grant.status, grant.body);
  const wrongOrigin = await httpsRequest(
    ca,
    "POST",
    "/api/sessions",
    {
      ...common,
      Origin: "https://wrong-origin.example.invalid:8443",
      Cookie: cookie,
      "Content-Type": "application/json",
    },
    payload,
  );
  if (wrongOrigin.status !== 403) {
    throw new Error("incorrect public URL or Origin was not denied");
  }
  if (secretPath !== undefined) {
    writeFileSync(
      secretPath,
      JSON.stringify({
        authorization: FIXTURE_AUTHORIZATION,
        cookie,
        ticket,
        terminal: TERMINAL_SENTINEL,
      }),
      { encoding: "utf8", flag: "wx", mode: 0o600 },
    );
  }
  await openWebSocket(
    ca,
    cookie,
    ticket,
    process.env.TTYGATE_FIXTURE_HOLD === "1",
  );

  process.stdout.write(`REVERSE_PROXY_SESSION_OK identity=${FIXTURE_IDENTITY}\n`);
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  if (process.argv[2] === "--scan-audit") {
    const auditPath = process.argv[3];
    const secretPath = process.argv[4];
    if (auditPath === undefined || secretPath === undefined) {
      throw new Error("audit and secret paths are required");
    }
    const secrets = Object.values(JSON.parse(readFileSync(secretPath, "utf8")));
    const count = scanAuditText(readFileSync(auditPath, "utf8"), secrets);
    process.stdout.write(`AUDIT_SCAN_OK records=${count}\n`);
  } else {
    const certificatePath = process.argv[2];
    if (certificatePath === undefined) {
      throw new Error("certificate path is required");
    }
    await runLifecycle(certificatePath, process.argv[3]);
  }
}
