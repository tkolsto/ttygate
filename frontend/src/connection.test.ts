import assert from "node:assert/strict";
import test from "node:test";

import type { SessionGrant, TargetPresentation } from "./api.ts";
import {
  TerminalConnectionController,
  webSocketUrl,
  type ConnectionSnapshot,
  type SocketPort,
  type TerminalPort,
} from "./connection.ts";
import {
  MAX_BINARY_BYTES,
  encodeServerControl,
} from "./protocol.ts";
import type { Scheduler, TerminalSize } from "./terminal-io.ts";

class ManualScheduler implements Scheduler {
  readonly pending = new Map<number, () => void>();
  #next = 0;

  set(_delayMilliseconds: number, callback: () => void): unknown {
    const handle = this.#next++;
    this.pending.set(handle, callback);
    return handle;
  }

  clear(handle: unknown): void {
    this.pending.delete(handle as number);
  }

  flush(): void {
    const callbacks = [...this.pending.values()];
    this.pending.clear();
    callbacks.forEach((callback) => callback());
  }
}

class FakeSocket implements SocketPort {
  binaryType = "";
  readyState = 0;
  bufferedAmount = 0;
  accumulateBufferedAmount = false;
  onopen: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent<unknown>) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  readonly sent: Array<string | Uint8Array> = [];
  closeCalls = 0;

  send(data: string | ArrayBuffer | ArrayBufferView): void {
    if (typeof data === "string") {
      this.sent.push(data);
    } else if (data instanceof ArrayBuffer) {
      this.sent.push(new Uint8Array(data));
      if (this.accumulateBufferedAmount) this.bufferedAmount += data.byteLength;
    } else {
      this.sent.push(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
      if (this.accumulateBufferedAmount) this.bufferedAmount += data.byteLength;
    }
  }

  close(): void {
    this.closeCalls += 1;
    this.readyState = 3;
  }

  open(): void {
    this.readyState = 1;
    this.onopen?.({} as Event);
  }

  message(data: unknown): void {
    this.onmessage?.({ data } as MessageEvent<unknown>);
  }

  transportClose(): void {
    this.readyState = 3;
    this.onclose?.({} as CloseEvent);
  }
}

class FakeTerminal implements TerminalPort {
  readonly writes: Uint8Array[] = [];
  readonly drains: Array<() => void> = [];
  readonly dataHandlers = new Set<(data: string) => void>();
  readonly binaryHandlers = new Set<(data: string) => void>();
  readonly resizeHandlers = new Set<(size: TerminalSize) => void>();
  focusCalls = 0;
  dimensions = { cols: 80, rows: 24 };

  write(data: Uint8Array, drained: () => void): void {
    this.writes.push(new Uint8Array(data));
    this.drains.push(drained);
  }

  onData(handler: (data: string) => void): () => void {
    this.dataHandlers.add(handler);
    return () => this.dataHandlers.delete(handler);
  }

  onBinary(handler: (data: string) => void): () => void {
    this.binaryHandlers.add(handler);
    return () => this.binaryHandlers.delete(handler);
  }

  onResize(handler: (size: TerminalSize) => void): () => void {
    this.resizeHandlers.add(handler);
    return () => this.resizeHandlers.delete(handler);
  }

  size(): TerminalSize {
    return this.dimensions;
  }

  focus(): void {
    this.focusCalls += 1;
  }

  input(data: string): void {
    this.dataHandlers.forEach((handler) => handler(data));
  }

  binary(data: string): void {
    this.binaryHandlers.forEach((handler) => handler(data));
  }

  resize(size: TerminalSize): void {
    this.dimensions = size;
    this.resizeHandlers.forEach((handler) => handler(size));
  }
}

interface Harness {
  controller: TerminalConnectionController;
  terminal: FakeTerminal;
  scheduler: ManualScheduler;
  sockets: FakeSocket[];
  urls: string[];
  states: ConnectionSnapshot[];
  grants: SessionGrant[];
  resolveGrant?: (grant: SessionGrant) => void;
}

function harness(options: {
  targets?: TargetPresentation[];
  grant?: SessionGrant;
  delayedGrant?: boolean;
} = {}): Harness {
  const terminal = new FakeTerminal();
  const scheduler = new ManualScheduler();
  const sockets: FakeSocket[] = [];
  const urls: string[] = [];
  const states: ConnectionSnapshot[] = [];
  const grants: SessionGrant[] = [];
  const grant = options.grant ?? {
    ticket: "opaque-ticket-secret",
    target: { name: "shell", readOnly: false },
  };
  let resolveGrant: ((grant: SessionGrant) => void) | undefined;
  const requestGrant = options.delayedGrant
    ? () => new Promise<SessionGrant>((resolve) => {
      resolveGrant = resolve;
    })
    : async () => {
      const issued = {
        ticket: grant.ticket,
        target: { ...grant.target },
      };
      grants.push(issued);
      return issued;
    };
  const result: Harness = {
    controller: new TerminalConnectionController({
      establishIdentity: async () => {},
      fetchTargets: async () => options.targets ?? [{ name: "shell", readOnly: false }],
      requestSessionGrant: requestGrant,
      createSocket: (url) => {
        urls.push(url);
        const socket = new FakeSocket();
        sockets.push(socket);
        return socket;
      },
      pageUrl: "https://terminal.example:7681/old?ticket=must-not-survive#credential",
      terminal,
      scheduler,
      onState: (state) => states.push(state),
    }),
    terminal,
    scheduler,
    sockets,
    urls,
    states,
    grants,
  };
  Object.defineProperty(result, "resolveGrant", {
    get: () => resolveGrant,
  });
  return result;
}

test("connection boot exposes stable identity and ready states with configured targets", async () => {
  const setup = harness({
    targets: [
      { name: "readonly", readOnly: true },
      { name: "shell", readOnly: false },
    ],
  });

  await setup.controller.start();

  assert.deepEqual(setup.states.map((state) => state.phase), [
    "establishing-identity",
    "ready",
  ]);
  assert.deepEqual(setup.states.at(-1)?.targets, [
    { name: "readonly", readOnly: true },
    { name: "shell", readOnly: false },
  ]);
});

test("bootstrap failure keeps terminal actions disabled and preserves internal-error", async () => {
  const setup = harness({ targets: [] });

  await setup.controller.start();
  assert.equal(setup.states.at(-1)?.phase, "internal-error");

  await setup.controller.connect("");

  assert.equal(setup.states.at(-1)?.phase, "internal-error");
  assert.equal(setup.sockets.length, 0);
});

test("ticket is the first socket message then discarded before input becomes active", async () => {
  const setup = harness();
  await setup.controller.start();
  await setup.controller.connect("shell");
  const socket = setup.sockets[0]!;

  assert.deepEqual(setup.states.slice(-2).map((state) => state.phase), [
    "requesting-authorization",
    "connecting",
  ]);
  assert.deepEqual(setup.urls, ["wss://terminal.example:7681/api/ws"]);
  assert.equal(socket.binaryType, "arraybuffer");
  assert.equal(setup.terminal.dataHandlers.size, 0);

  socket.open();

  assert.equal(socket.sent[0], JSON.stringify({ ticket: "opaque-ticket-secret" }));
  assert.equal(
    socket.sent[1],
    '{"version":1,"type":"resize","cols":80,"rows":24}',
    "the measured initial resize precedes terminal input",
  );
  assert.equal(setup.grants[0]?.ticket, "", "grant no longer retains the ticket");
  assert.equal(setup.states.at(-1)?.phase, "active");
  assert.equal(setup.terminal.dataHandlers.size, 1);
  assert.equal(setup.terminal.binaryHandlers.size, 1);
  assert.equal(setup.terminal.resizeHandlers.size, 1);
  assert.equal(setup.terminal.focusCalls, 1);
  assert.ok(setup.states.every((state) => !JSON.stringify(state).includes("opaque-ticket-secret")));
  assert.ok(setup.urls.every((url) => !url.includes("opaque-ticket-secret")));
});

test("active connection sends bounded opaque input and codec resize controls", async () => {
  const setup = harness();
  await setup.controller.start();
  await setup.controller.connect("shell");
  const socket = setup.sockets[0]!;
  socket.open();

  setup.terminal.input(`${"a".repeat(MAX_BINARY_BYTES - 1)}é`);
  setup.terminal.binary(String.fromCharCode(0xff, 0x00, 0x80));
  setup.terminal.resize({ cols: 100, rows: 40 });
  setup.scheduler.flush();

  const binary = socket.sent.filter((value): value is Uint8Array => value instanceof Uint8Array);
  assert.deepEqual(binary.map((value) => value.byteLength), [
    MAX_BINARY_BYTES - 1,
    2,
    3,
  ]);
  assert.deepEqual([...binary[2]!], [0xff, 0x00, 0x80]);
  assert.equal(
    socket.sent.at(-1),
    '{"version":1,"type":"resize","cols":100,"rows":40}',
  );
});

test("read-only target keeps output and resize but never attaches input", async () => {
  const setup = harness({
    targets: [{ name: "readonly", readOnly: true }],
    grant: {
      ticket: "read-only-ticket",
      target: { name: "readonly", readOnly: true },
    },
  });
  await setup.controller.start();
  await setup.controller.connect("readonly");
  const socket = setup.sockets[0]!;
  socket.open();

  assert.equal(setup.states.at(-1)?.readOnly, true);
  assert.equal(setup.terminal.dataHandlers.size, 0);
  assert.equal(setup.terminal.binaryHandlers.size, 0);
  assert.equal(setup.terminal.resizeHandlers.size, 1);

  const output = new Uint8Array([0xff, 0x00, 0x58]);
  socket.message(output.buffer);
  assert.deepEqual(setup.terminal.writes, [output]);
});

test("server controls map to distinct terminal states and portable exit status", async () => {
  for (const [control, expected] of [
    [{ type: "close", reason: "timeout" }, "timed-out"],
    [{ type: "close", reason: "policy" }, "denied"],
    [{ type: "close", reason: "protocol-error" }, "protocol-error"],
    [{ type: "close", reason: "internal-error" }, "internal-error"],
    [{ type: "close", reason: "transport-error" }, "transport-disconnected"],
  ] as const) {
    const setup = harness();
    await setup.controller.start();
    await setup.controller.connect("shell");
    const socket = setup.sockets[0]!;
    socket.open();
    socket.message(encodeServerControl(control));
    assert.equal(setup.states.at(-1)?.phase, expected);
  }

  const setup = harness();
  await setup.controller.start();
  await setup.controller.connect("shell");
  const socket = setup.sockets[0]!;
  socket.open();
  socket.message(encodeServerControl({
    type: "exit-status",
    status: { kind: "code", code: 23 },
  }));
  socket.message(encodeServerControl({ type: "close", reason: "exited" }));
  assert.equal(setup.states.at(-1)?.phase, "exited");
  assert.deepEqual(setup.states.at(-1)?.exitStatus, { kind: "code", code: 23 });
});

test("curated server errors and malformed frames fail into stable distinct states", async () => {
  for (const [code, expected] of [
    ["authorization-denied", "denied"],
    ["session-denied", "denied"],
    ["protocol-error", "protocol-error"],
    ["session-unavailable", "internal-error"],
  ] as const) {
    const setup = harness();
    await setup.controller.start();
    await setup.controller.connect("shell");
    const socket = setup.sockets[0]!;
    socket.open();
    socket.message(encodeServerControl({
      type: "error",
      code,
      message: "A safe server message.",
    }));
    assert.equal(setup.states.at(-1)?.phase, expected);
    assert.ok(!JSON.stringify(setup.states.at(-1)).includes("A safe server message."));
  }

  const malformed = harness();
  await malformed.controller.start();
  await malformed.controller.connect("shell");
  malformed.sockets[0]!.open();
  malformed.sockets[0]!.message('{"hostile":"<img onerror=credential>"}');
  assert.equal(malformed.states.at(-1)?.phase, "protocol-error");
  assert.ok(!JSON.stringify(malformed.states.at(-1)).includes("credential"));
});

test("frontend_exposes_stable_distinct_ssh_failure_states", async () => {
  for (const [code, expected] of [
    ["ssh-host-key-failed", "ssh-host-key-failed"],
    ["ssh-connection-failed", "ssh-connection-failed"],
    ["ssh-authentication-failed", "ssh-authentication-failed"],
    ["ssh-policy-denied", "ssh-policy-denied"],
    ["ssh-failed", "ssh-failed"],
  ] as const) {
    const setup = harness();
    await setup.controller.start();
    await setup.controller.connect("shell");
    const socket = setup.sockets[0]!;
    socket.open();
    socket.message(encodeServerControl({
      type: "error",
      code,
      message: "This server text must not select the frontend state.",
    }));
    assert.equal(setup.states.at(-1)?.phase, expected);
    assert.ok(!JSON.stringify(setup.states.at(-1)).includes("server text"));
  }
});

test("hostile_protocol_values_cannot_select_any_ssh_argument", async () => {
  const sentinels = [
    "-oProxyCommand=credential",
    "root@host.example",
    "/tmp/identity-secret",
    "ssh.example.test",
  ];

  for (const sentinel of sentinels) {
    const setup = harness();
    await setup.controller.start();
    await setup.controller.connect("shell");
    const socket = setup.sockets[0]!;
    socket.open();
    socket.message(JSON.stringify({
      version: 1,
      type: "error",
      code: "ssh-failed",
      message: "The SSH session could not be established safely.",
      sshArgument: sentinel,
    }));

    assert.equal(setup.states.at(-1)?.phase, "protocol-error");
    assert.ok(socket.sent.every((value) => !String(value).includes(sentinel)));
    assert.ok(!JSON.stringify(setup.states.at(-1)).includes(sentinel));
  }
});

test("undrained terminal output fails closed instead of growing without bound", async () => {
  const setup = harness();
  await setup.controller.start();
  await setup.controller.connect("shell");
  const socket = setup.sockets[0]!;
  socket.open();

  for (let index = 0; index < 17; index += 1) {
    socket.message(new Uint8Array(MAX_BINARY_BYTES).buffer);
  }

  assert.equal(setup.states.at(-1)?.phase, "internal-error");
  assert.equal(socket.closeCalls, 1);
  assert.equal(setup.terminal.writes.length, 1, "xterm drain gates later writes");
});

test("terminal input fails closed when WebSocket buffered bytes exceed the client limit", async () => {
  const setup = harness();
  await setup.controller.start();
  await setup.controller.connect("shell");
  const socket = setup.sockets[0]!;
  socket.open();
  socket.accumulateBufferedAmount = true;

  setup.terminal.input("x".repeat((MAX_BINARY_BYTES * 17) + 1));

  assert.equal(setup.states.at(-1)?.phase, "internal-error");
  assert.equal(socket.closeCalls, 1);
  assert.equal(setup.terminal.dataHandlers.size, 0);
  assert.equal(setup.terminal.binaryHandlers.size, 0);
});

test("explicit close is codec-ordered, disables handlers, and becomes user-closed", async () => {
  const setup = harness();
  await setup.controller.start();
  await setup.controller.connect("shell");
  const socket = setup.sockets[0]!;
  socket.open();

  setup.controller.close();

  assert.equal(
    socket.sent.at(-1),
    '{"version":1,"type":"close"}',
  );
  assert.equal(socket.closeCalls, 1);
  assert.equal(setup.states.at(-1)?.phase, "user-closed");
  assert.equal(setup.terminal.dataHandlers.size, 0);
  assert.equal(setup.terminal.binaryHandlers.size, 0);
  assert.equal(setup.terminal.resizeHandlers.size, 0);
  assert.equal(setup.scheduler.pending.size, 0);
});

test("repeated connect and close cycles leave no duplicate handlers or timers", async () => {
  const setup = harness();
  await setup.controller.start();

  for (let cycle = 0; cycle < 5; cycle += 1) {
    await setup.controller.connect("shell");
    const socket = setup.sockets[cycle]!;
    socket.open();
    assert.equal(setup.terminal.dataHandlers.size, 1);
    assert.equal(setup.terminal.binaryHandlers.size, 1);
    assert.equal(setup.terminal.resizeHandlers.size, 1);
    setup.controller.close();
    assert.equal(setup.terminal.dataHandlers.size, 0);
    assert.equal(setup.terminal.binaryHandlers.size, 0);
    assert.equal(setup.terminal.resizeHandlers.size, 0);
    assert.equal(setup.scheduler.pending.size, 0);
  }

  assert.equal(setup.sockets.length, 5);
  assert.ok(setup.sockets.every((socket) => socket.closeCalls === 1));
});

test("stale grants sockets timers and drains cannot mutate a replacement connection", async () => {
  const setup = harness({ delayedGrant: true });
  await setup.controller.start();
  const first = setup.controller.connect("shell");
  const resolveFirst = setup.resolveGrant!;
  setup.controller.close();
  resolveFirst({
    ticket: "stale-ticket-secret",
    target: { name: "shell", readOnly: false },
  });
  await first;
  assert.equal(setup.sockets.length, 0);
  assert.ok(setup.states.every((state) => !JSON.stringify(state).includes("stale-ticket-secret")));

  const current = harness();
  await current.controller.start();
  await current.controller.connect("shell");
  const oldSocket = current.sockets[0]!;
  oldSocket.open();
  oldSocket.message(new Uint8Array([1]).buffer);
  const staleDrain = current.terminal.drains[0]!;
  current.controller.close();
  oldSocket.message(encodeServerControl({ type: "close", reason: "timeout" }));
  oldSocket.transportClose();
  staleDrain();
  current.scheduler.flush();
  assert.equal(current.states.at(-1)?.phase, "user-closed");
});

test("transport loss and connection deadline are distinct and never reconnect", async () => {
  const disconnected = harness();
  await disconnected.controller.start();
  await disconnected.controller.connect("shell");
  disconnected.sockets[0]!.open();
  disconnected.sockets[0]!.transportClose();
  assert.equal(disconnected.states.at(-1)?.phase, "transport-disconnected");
  assert.equal(disconnected.sockets.length, 1);

  const timedOut = harness();
  await timedOut.controller.start();
  await timedOut.controller.connect("shell");
  timedOut.scheduler.flush();
  assert.equal(timedOut.states.at(-1)?.phase, "timed-out");
  assert.equal(timedOut.sockets.length, 1);
  assert.equal(timedOut.sockets[0]?.closeCalls, 1);
});

test("authorization deadline times out a hung grant and ignores its late ticket", async () => {
  const setup = harness({ delayedGrant: true });
  await setup.controller.start();
  const connecting = setup.controller.connect("shell");

  setup.scheduler.flush();

  assert.equal(setup.states.at(-1)?.phase, "timed-out");
  const resolveGrant = setup.resolveGrant!;
  const lateGrant = {
    ticket: "late-ticket-secret",
    target: { name: "shell", readOnly: false },
  };
  resolveGrant(lateGrant);
  await connecting;
  assert.equal(lateGrant.ticket, "");
  assert.equal(setup.sockets.length, 0);
  assert.ok(setup.states.every((state) => !JSON.stringify(state).includes("late-ticket-secret")));
});

test("WebSocket URL is fixed to same-origin path without credentials query or fragment", () => {
  assert.equal(
    webSocketUrl("http://user:password@127.0.0.1:7681/path?ticket=secret#credential"),
    "ws://127.0.0.1:7681/api/ws",
  );
  assert.equal(
    webSocketUrl("https://ttygate.example/app"),
    "wss://ttygate.example/api/ws",
  );
});
