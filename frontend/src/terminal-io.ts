import { MAX_BINARY_BYTES, MAX_DIMENSION } from "./protocol.ts";

export const RESIZE_DEBOUNCE_MILLISECONDS = 50;
export const OUTPUT_QUEUE_LIMIT = 1024 * 1024;

export interface TerminalSize {
  cols: number;
  rows: number;
}

export interface Scheduler {
  set(delayMilliseconds: number, callback: () => void): unknown;
  clear(handle: unknown): void;
}

const browserScheduler: Scheduler = {
  set: (delayMilliseconds, callback) => globalThis.setTimeout(callback, delayMilliseconds),
  clear: (handle) => globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>),
};

export function chunkUtf8Input(text: string): Uint8Array[] {
  if (text.length === 0) return [];
  const encoder = new TextEncoder();
  const chunks: Uint8Array[] = [];
  let pending: number[] = [];

  for (const character of text) {
    const encoded = encoder.encode(character);
    if (pending.length + encoded.byteLength > MAX_BINARY_BYTES) {
      chunks.push(Uint8Array.from(pending));
      pending = [];
    }
    pending.push(...encoded);
  }
  if (pending.length > 0) chunks.push(Uint8Array.from(pending));
  return chunks;
}

export function chunkBinaryInput(data: Uint8Array): Uint8Array[] {
  const chunks: Uint8Array[] = [];
  for (let offset = 0; offset < data.byteLength; offset += MAX_BINARY_BYTES) {
    chunks.push(data.slice(offset, offset + MAX_BINARY_BYTES));
  }
  return chunks;
}

export class ResizeCoalescer {
  readonly #send: (size: TerminalSize) => void;
  readonly #scheduler: Scheduler;
  #pending: TerminalSize | undefined;
  #lastSent: TerminalSize | undefined;
  #timer: unknown;
  #disposed = false;

  constructor(
    send: (size: TerminalSize) => void,
    scheduler: Scheduler = browserScheduler,
  ) {
    this.#send = send;
    this.#scheduler = scheduler;
  }

  offer(size: TerminalSize): void {
    if (this.#disposed) throw new Error("resize coalescer is disposed");
    validateSize(size);
    if (sameSize(size, this.#lastSent) || sameSize(size, this.#pending)) return;
    this.#pending = { ...size };
    if (this.#timer !== undefined) return;
    this.#timer = this.#scheduler.set(RESIZE_DEBOUNCE_MILLISECONDS, () => {
      this.#timer = undefined;
      const pending = this.#pending;
      this.#pending = undefined;
      if (this.#disposed || pending === undefined || sameSize(pending, this.#lastSent)) return;
      this.#lastSent = pending;
      this.#send(pending);
    });
  }

  sendNow(size: TerminalSize): void {
    if (this.#disposed) throw new Error("resize coalescer is disposed");
    validateSize(size);
    this.#pending = undefined;
    if (this.#timer !== undefined) {
      this.#scheduler.clear(this.#timer);
      this.#timer = undefined;
    }
    if (sameSize(size, this.#lastSent)) return;
    this.#lastSent = { ...size };
    this.#send(size);
  }

  dispose(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    this.#pending = undefined;
    if (this.#timer !== undefined) {
      this.#scheduler.clear(this.#timer);
      this.#timer = undefined;
    }
  }
}

export class BoundedTerminalWriter {
  readonly #write: (bytes: Uint8Array, drained: () => void) => void;
  readonly #overflow: () => void;
  readonly #limit: number;
  readonly #queue: Uint8Array[] = [];
  #pendingBytes = 0;
  #writing = false;
  #failed = false;
  #disposed = false;
  #generation = 0;

  constructor(
    write: (bytes: Uint8Array, drained: () => void) => void,
    overflow: () => void,
    limit = OUTPUT_QUEUE_LIMIT,
  ) {
    this.#write = write;
    this.#overflow = overflow;
    this.#limit = limit;
  }

  get pendingBytes(): number {
    return this.#pendingBytes;
  }

  enqueue(data: Uint8Array): boolean {
    if (this.#disposed || this.#failed) return false;
    if (data.byteLength === 0) return true;
    if (this.#pendingBytes + data.byteLength > this.#limit) {
      this.#failed = true;
      this.#overflow();
      return false;
    }
    const owned = new Uint8Array(data);
    this.#pendingBytes += owned.byteLength;
    this.#queue.push(owned);
    this.#pump();
    return true;
  }

  dispose(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    this.#generation += 1;
    this.#queue.length = 0;
    this.#pendingBytes = 0;
    this.#writing = false;
  }

  #pump(): void {
    if (this.#writing || this.#disposed || this.#failed) return;
    const next = this.#queue.shift();
    if (next === undefined) return;
    this.#writing = true;
    const generation = this.#generation;
    this.#write(next, () => {
      if (this.#disposed || generation !== this.#generation) return;
      this.#pendingBytes -= next.byteLength;
      this.#writing = false;
      this.#pump();
    });
  }
}

function validateSize(size: TerminalSize): void {
  if (
    !Number.isInteger(size.cols)
    || !Number.isInteger(size.rows)
    || size.cols < 1
    || size.rows < 1
    || size.cols > MAX_DIMENSION
    || size.rows > MAX_DIMENSION
  ) {
    throw new Error("invalid terminal dimensions");
  }
}

function sameSize(left: TerminalSize | undefined, right: TerminalSize | undefined): boolean {
  return left !== undefined
    && right !== undefined
    && left.cols === right.cols
    && left.rows === right.rows;
}
