import { randomBytes } from "node:crypto";
import { request } from "node:http";
import { connect } from "node:net";

const origin = "http://127.0.0.1:7681";

function post(path, body, cookie) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? "" : JSON.stringify(body);
    const headers = {
      Origin: origin,
      "Content-Length": Buffer.byteLength(payload),
    };
    if (payload !== "") headers["Content-Type"] = "application/json";
    if (cookie !== undefined) headers.Cookie = cookie;
    const outgoing = request(
      {
        hostname: "127.0.0.1",
        port: 7681,
        path,
        method: "POST",
        headers,
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          resolve({
            status: response.statusCode,
            headers: response.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    );
    outgoing.once("error", reject);
    outgoing.end(payload);
  });
}

function maskedFrame(opcode, value) {
  const payload = Buffer.from(value);
  if (payload.length >= 126) throw new Error("fixture frame exceeded short bound");
  const mask = randomBytes(4);
  const frame = Buffer.alloc(2 + mask.length + payload.length);
  frame[0] = 0x80 | opcode;
  frame[1] = 0x80 | payload.length;
  mask.copy(frame, 2);
  for (let index = 0; index < payload.length; index += 1) {
    frame[6 + index] = payload[index] ^ mask[index % 4];
  }
  return frame;
}

function openSession(cookie, ticket) {
  return new Promise((resolve, reject) => {
    const socket = connect(7681, "127.0.0.1");
    let response = Buffer.alloc(0);
    socket.once("error", reject);
    socket.once("connect", () => {
      const key = randomBytes(16).toString("base64");
      socket.write(
        "GET /api/ws HTTP/1.1\r\n" +
          "Host: 127.0.0.1:7681\r\n" +
          "Upgrade: websocket\r\n" +
          "Connection: Upgrade\r\n" +
          `Sec-WebSocket-Key: ${key}\r\n` +
          "Sec-WebSocket-Version: 13\r\n" +
          `Origin: ${origin}\r\n` +
          `Cookie: ${cookie}\r\n\r\n`,
      );
    });
    const onData = (chunk) => {
      response = Buffer.concat([response, chunk]);
      const boundary = response.indexOf("\r\n\r\n");
      if (boundary === -1) return;
      socket.off("data", onData);
      const headers = response.subarray(0, boundary).toString("ascii");
      if (!headers.startsWith("HTTP/1.1 101 ")) {
        reject(new Error("WebSocket upgrade was rejected"));
        socket.destroy();
        return;
      }
      socket.write(maskedFrame(0x1, JSON.stringify({ ticket })));
      setTimeout(() => {
        socket.write(maskedFrame(0x2, "sleep 300\n"));
        resolve(socket);
      }, 500);
    };
    socket.on("data", onData);
  });
}

const identity = await post("/api/identity");
if (identity.status !== 204) throw new Error("identity request failed");
const setCookie = identity.headers["set-cookie"]?.[0];
if (setCookie === undefined) throw new Error("identity cookie missing");
const cookie = setCookie.split(";", 1)[0];

const grant = await post("/api/sessions", { target: "local-shell" }, cookie);
if (grant.status !== 201) throw new Error("session grant failed");
const ticket = JSON.parse(grant.body).ticket;
if (typeof ticket !== "string") throw new Error("session ticket missing");

const socket = await openSession(cookie, ticket);
await new Promise((resolve) => setTimeout(resolve, 1000));
process.stdout.write("SESSION_READY\n");

const hold = setInterval(() => {}, 60_000);
const stop = () => {
  clearInterval(hold);
  socket.destroy();
  process.exit(0);
};
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
