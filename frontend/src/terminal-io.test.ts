import assert from "node:assert/strict";
import test from "node:test";

import { MAX_BINARY_BYTES } from "./protocol.ts";
import {
  BoundedTerminalWriter,
  OUTPUT_QUEUE_LIMIT,
  ResizeCoalescer,
  chunkBinaryInput,
  chunkUtf8Input,
  type Scheduler,
} from "./terminal-io.ts";

test("UTF-8 input chunks stay bounded and preserve code point boundaries", () => {
  const text = `${"a".repeat(MAX_BINARY_BYTES - 1)}é🙂${"z".repeat(MAX_BINARY_BYTES)}`;
  const chunks = chunkUtf8Input(text);
  const decoder = new TextDecoder("utf-8", { fatal: true });

  assert.ok(chunks.length >= 3);
  assert.ok(chunks.every((chunk) => chunk.byteLength <= MAX_BINARY_BYTES));
  assert.equal(chunks.map((chunk) => decoder.decode(chunk)).join(""), text);
  assert.deepEqual(chunkUtf8Input(""), []);
});

test("UTF-8 input permits an exact maximum chunk and moves a whole multibyte value", () => {
  const exact = chunkUtf8Input("a".repeat(MAX_BINARY_BYTES));
  assert.equal(exact.length, 1);
  assert.equal(exact[0]?.byteLength, MAX_BINARY_BYTES);

  const crossing = chunkUtf8Input(`${"a".repeat(MAX_BINARY_BYTES - 1)}é`);
  assert.deepEqual(crossing.map((chunk) => chunk.byteLength), [MAX_BINARY_BYTES - 1, 2]);
  assert.equal(new TextDecoder().decode(crossing[1]), "é");
});

test("binary input remains byte-for-byte opaque across bounded chunks", () => {
  const input = new Uint8Array(MAX_BINARY_BYTES + 3);
  input[0] = 0xff;
  input[MAX_BINARY_BYTES - 1] = 0x80;
  input[MAX_BINARY_BYTES] = 0x00;
  input[MAX_BINARY_BYTES + 2] = 0xfe;

  const chunks = chunkBinaryInput(input);

  assert.deepEqual(chunks.map((chunk) => chunk.byteLength), [MAX_BINARY_BYTES, 3]);
  assert.deepEqual(
    new Uint8Array(chunks.flatMap((chunk) => [...chunk])),
    input,
  );
  input[0] = 0;
  assert.equal(chunks[0]?.[0], 0xff, "chunks own their bytes");
  assert.deepEqual(chunkBinaryInput(new Uint8Array()), []);
});

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

test("resize coalescing validates dimensions and sends only the latest distinct size", () => {
  const scheduler = new ManualScheduler();
  const sent: Array<{ cols: number; rows: number }> = [];
  const resize = new ResizeCoalescer((size) => sent.push(size), scheduler);

  resize.offer({ cols: 80, rows: 24 });
  resize.offer({ cols: 100, rows: 40 });
  resize.offer({ cols: 100, rows: 40 });
  assert.equal(scheduler.pending.size, 1);
  scheduler.flush();
  assert.deepEqual(sent, [{ cols: 100, rows: 40 }]);

  resize.offer({ cols: 100, rows: 40 });
  assert.equal(scheduler.pending.size, 0);
  resize.offer({ cols: 120, rows: 50 });
  scheduler.flush();
  assert.deepEqual(sent, [
    { cols: 100, rows: 40 },
    { cols: 120, rows: 50 },
  ]);

  for (const invalid of [
    { cols: 0, rows: 24 },
    { cols: 80, rows: 0 },
    { cols: 4_097, rows: 24 },
    { cols: 80.5, rows: 24 },
  ]) {
    assert.throws(() => resize.offer(invalid));
  }
});

test("initial resize can be sent immediately and suppresses an identical observer event", () => {
  const scheduler = new ManualScheduler();
  const sent: Array<{ cols: number; rows: number }> = [];
  const resize = new ResizeCoalescer((size) => sent.push(size), scheduler);

  resize.sendNow({ cols: 80, rows: 24 });
  resize.offer({ cols: 80, rows: 24 });

  assert.deepEqual(sent, [{ cols: 80, rows: 24 }]);
  assert.equal(scheduler.pending.size, 0);
});

test("disposing resize coalescing removes its timer and prevents late sends", () => {
  const scheduler = new ManualScheduler();
  const sent: Array<{ cols: number; rows: number }> = [];
  const resize = new ResizeCoalescer((size) => sent.push(size), scheduler);
  resize.offer({ cols: 80, rows: 24 });

  resize.dispose();
  scheduler.flush();

  assert.equal(scheduler.pending.size, 0);
  assert.deepEqual(sent, []);
  assert.throws(() => resize.offer({ cols: 100, rows: 40 }));
});

test("terminal output writes in order and accounts bytes only after drain callbacks", () => {
  const writes: Uint8Array[] = [];
  const drains: Array<() => void> = [];
  const writer = new BoundedTerminalWriter((bytes, drained) => {
    writes.push(bytes);
    drains.push(drained);
  }, () => assert.fail("unexpected overflow"));

  assert.equal(writer.enqueue(new Uint8Array([1, 2])), true);
  assert.equal(writer.enqueue(new Uint8Array([3])), true);
  assert.equal(writer.pendingBytes, 3);
  assert.deepEqual(writes.map((bytes) => [...bytes]), [[1, 2]]);

  drains.shift()?.();
  assert.equal(writer.pendingBytes, 1);
  assert.deepEqual(writes.map((bytes) => [...bytes]), [[1, 2], [3]]);
  drains.shift()?.();
  assert.equal(writer.pendingBytes, 0);
});

test("terminal output fails closed at the hard queue limit and ignores stale drains", () => {
  const drains: Array<() => void> = [];
  let overflows = 0;
  const writer = new BoundedTerminalWriter((_bytes, drained) => {
    drains.push(drained);
  }, () => {
    overflows += 1;
  });

  for (let offset = 0; offset < OUTPUT_QUEUE_LIMIT; offset += MAX_BINARY_BYTES) {
    assert.equal(writer.enqueue(new Uint8Array(MAX_BINARY_BYTES)), true);
  }
  assert.equal(writer.pendingBytes, OUTPUT_QUEUE_LIMIT);
  assert.equal(writer.enqueue(new Uint8Array([1])), false);
  assert.equal(overflows, 1);
  assert.equal(writer.enqueue(new Uint8Array([2])), false);
  assert.equal(overflows, 1);

  writer.dispose();
  drains.forEach((drain) => drain());
  assert.equal(writer.pendingBytes, 0);
});
