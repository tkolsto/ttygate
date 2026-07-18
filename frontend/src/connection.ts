import {
  FrontendApiError,
  type SessionGrant,
  type TargetPresentation,
} from "./api.ts";
import {
  decodeServerBinary,
  decodeServerControl,
  encodeClientControl,
  type CloseReason,
  type ExitStatus,
  type ServerControl,
} from "./protocol.ts";
import {
  BoundedTerminalWriter,
  ResizeCoalescer,
  chunkBinaryInput,
  chunkUtf8Input,
  type Scheduler,
  type TerminalSize,
} from "./terminal-io.ts";

const CONNECTION_DEADLINE_MILLISECONDS = 10_000;
const SOCKET_OPEN = 1;

export type ConnectionPhase =
  | "establishing-identity"
  | "ready"
  | "requesting-authorization"
  | "connecting"
  | "active"
  | "denied"
  | "protocol-error"
  | "internal-error"
  | "timed-out"
  | "exited"
  | "transport-disconnected"
  | "user-closed";

export interface ConnectionSnapshot {
  phase: ConnectionPhase;
  targets: readonly TargetPresentation[];
  activeTarget?: string;
  readOnly?: boolean;
  exitStatus?: ExitStatus;
}

export interface SocketPort {
  binaryType: string;
  readonly readyState: number;
  onopen: ((event: Event) => void) | null;
  onmessage: ((event: MessageEvent<unknown>) => void) | null;
  onclose: ((event: CloseEvent) => void) | null;
  onerror: ((event: Event) => void) | null;
  send(data: string | ArrayBuffer | ArrayBufferView): void;
  close(): void;
}

export interface TerminalPort {
  write(data: Uint8Array, drained: () => void): void;
  onData(handler: (data: string) => void): () => void;
  onBinary(handler: (data: string) => void): () => void;
  onResize(handler: (size: TerminalSize) => void): () => void;
  size(): TerminalSize;
  focus(): void;
}

export interface ConnectionDependencies {
  establishIdentity(): Promise<void>;
  fetchTargets(): Promise<TargetPresentation[]>;
  requestSessionGrant(target: string): Promise<SessionGrant>;
  createSocket(url: string): SocketPort;
  pageUrl: string;
  terminal: TerminalPort;
  onState(snapshot: ConnectionSnapshot): void;
  scheduler?: Scheduler;
}

const defaultScheduler: Scheduler = {
  set: (delayMilliseconds, callback) => globalThis.setTimeout(callback, delayMilliseconds),
  clear: (handle) => globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>),
};

export function webSocketUrl(pageUrl: string): string {
  const url = new URL(pageUrl);
  if (url.protocol === "http:") url.protocol = "ws:";
  else if (url.protocol === "https:") url.protocol = "wss:";
  else throw new Error("unsupported page protocol");
  url.username = "";
  url.password = "";
  url.pathname = "/api/ws";
  url.search = "";
  url.hash = "";
  return url.toString();
}

export class TerminalConnectionController {
  readonly #dependencies: ConnectionDependencies;
  readonly #scheduler: Scheduler;
  #generation = 0;
  #targets: TargetPresentation[] = [];
  #snapshot: ConnectionSnapshot = {
    phase: "establishing-identity",
    targets: [],
  };
  #socket: SocketPort | undefined;
  #connectionTimer: unknown;
  #inputDisposers: Array<() => void> = [];
  #resize: ResizeCoalescer | undefined;
  #output: BoundedTerminalWriter | undefined;
  #exitStatus: ExitStatus | undefined;

  constructor(dependencies: ConnectionDependencies) {
    this.#dependencies = dependencies;
    this.#scheduler = dependencies.scheduler ?? defaultScheduler;
  }

  get snapshot(): ConnectionSnapshot {
    return this.#snapshot;
  }

  async start(): Promise<void> {
    const generation = this.#replaceConnection(false);
    this.#emit({ phase: "establishing-identity", targets: [] });
    try {
      await this.#dependencies.establishIdentity();
      if (!this.#isCurrent(generation)) return;
      const targets = await this.#dependencies.fetchTargets();
      if (!this.#isCurrent(generation)) return;
      if (targets.length === 0) {
        this.#finish("internal-error");
        return;
      }
      this.#targets = targets.map((target) => ({ ...target }));
      this.#emit({ phase: "ready", targets: this.#targets });
    } catch (error) {
      if (!this.#isCurrent(generation)) return;
      this.#finish(apiPhase(error));
    }
  }

  async connect(targetName: string): Promise<void> {
    const configured = this.#targets.find((target) => target.name === targetName);
    const generation = this.#replaceConnection(true);
    if (configured === undefined) {
      this.#emit({ phase: "denied", targets: this.#targets });
      return;
    }
    this.#emit({
      phase: "requesting-authorization",
      targets: this.#targets,
      activeTarget: configured.name,
      readOnly: configured.readOnly,
    });
    this.#connectionTimer = this.#scheduler.set(CONNECTION_DEADLINE_MILLISECONDS, () => {
      if (!this.#isCurrent(generation)) return;
      this.#finish("timed-out", configured);
    });

    let grant: SessionGrant;
    try {
      grant = await this.#dependencies.requestSessionGrant(targetName);
    } catch (error) {
      if (!this.#isCurrent(generation)) return;
      this.#finish(apiPhase(error), configured);
      return;
    }
    if (!this.#isCurrent(generation)) {
      grant.ticket = "";
      return;
    }
    if (grant.target.name !== targetName) {
      grant.ticket = "";
      this.#finish("internal-error", configured);
      return;
    }

    let ticket = grant.ticket;
    grant.ticket = "";
    const target = { ...grant.target };
    let socket: SocketPort;
    try {
      socket = this.#dependencies.createSocket(webSocketUrl(this.#dependencies.pageUrl));
    } catch {
      ticket = "";
      this.#finish("internal-error", target);
      return;
    }
    if (!this.#isCurrent(generation)) {
      ticket = "";
      socket.close();
      return;
    }

    this.#socket = socket;
    socket.binaryType = "arraybuffer";
    socket.onopen = () => {
      if (!this.#isCurrent(generation) || socket !== this.#socket) {
        ticket = "";
        return;
      }
      this.#clearConnectionTimer();
      try {
        socket.send(JSON.stringify({ ticket }));
      } catch {
        ticket = "";
        this.#finish("internal-error", target);
        return;
      }
      ticket = "";
      this.#activate(generation, socket, target);
    };
    socket.onmessage = (event) => {
      if (!this.#isCurrent(generation) || socket !== this.#socket) return;
      this.#receive(generation, event.data, target);
    };
    socket.onclose = () => {
      if (!this.#isCurrent(generation) || socket !== this.#socket) return;
      this.#finish("transport-disconnected", target);
    };
    socket.onerror = () => {
      if (!this.#isCurrent(generation) || socket !== this.#socket) return;
      this.#finish("transport-disconnected", target);
    };
    this.#emit({
      phase: "connecting",
      targets: this.#targets,
      activeTarget: target.name,
      readOnly: target.readOnly,
    });
  }

  close(): void {
    const target = currentTarget(this.#snapshot);
    this.#replaceConnection(true);
    this.#emit({
      phase: "user-closed",
      targets: this.#targets,
      ...(target === undefined ? {} : {
        activeTarget: target.name,
        readOnly: target.readOnly,
      }),
      ...(this.#exitStatus === undefined ? {} : { exitStatus: this.#exitStatus }),
    });
  }

  #activate(
    generation: number,
    socket: SocketPort,
    target: TargetPresentation,
  ): void {
    if (!this.#isCurrent(generation)) return;
    this.#output = new BoundedTerminalWriter(
      (bytes, drained) => {
        if (!this.#isCurrent(generation)) return;
        try {
          this.#dependencies.terminal.write(bytes, drained);
        } catch {
          this.#finish("internal-error", target);
        }
      },
      () => {
        if (this.#isCurrent(generation)) this.#finish("internal-error", target);
      },
    );
    this.#resize = new ResizeCoalescer((size) => {
      if (!this.#isCurrent(generation) || socket.readyState !== SOCKET_OPEN) return;
      try {
        socket.send(encodeClientControl({ type: "resize", ...size }));
      } catch {
        this.#finish("transport-disconnected", target);
      }
    }, this.#scheduler);
    this.#inputDisposers.push(this.#dependencies.terminal.onResize((size) => {
      if (this.#isCurrent(generation)) this.#resize?.offer(size);
    }));
    this.#resize.sendNow(this.#dependencies.terminal.size());

    if (!target.readOnly) {
      this.#inputDisposers.push(this.#dependencies.terminal.onData((data) => {
        for (const chunk of chunkUtf8Input(data)) this.#sendBinary(generation, socket, chunk, target);
      }));
      this.#inputDisposers.push(this.#dependencies.terminal.onBinary((data) => {
        const bytes = Uint8Array.from(data, (character) => character.charCodeAt(0) & 0xff);
        for (const chunk of chunkBinaryInput(bytes)) {
          this.#sendBinary(generation, socket, chunk, target);
        }
      }));
    }
    this.#emit({
      phase: "active",
      targets: this.#targets,
      activeTarget: target.name,
      readOnly: target.readOnly,
    });
    this.#dependencies.terminal.focus();
  }

  #sendBinary(
    generation: number,
    socket: SocketPort,
    data: Uint8Array,
    target: TargetPresentation,
  ): void {
    if (!this.#isCurrent(generation) || socket.readyState !== SOCKET_OPEN) return;
    try {
      socket.send(data);
    } catch {
      this.#finish("transport-disconnected", target);
    }
  }

  #receive(generation: number, data: unknown, target: TargetPresentation): void {
    try {
      if (typeof data === "string") {
        this.#receiveControl(decodeServerControl(data), target);
        return;
      }
      if (data instanceof ArrayBuffer) {
        const frame = decodeServerBinary(new Uint8Array(data));
        this.#output?.enqueue(frame.data);
        return;
      }
      this.#finish("protocol-error", target);
    } catch {
      if (this.#isCurrent(generation)) this.#finish("protocol-error", target);
    }
  }

  #receiveControl(control: ServerControl, target: TargetPresentation): void {
    switch (control.type) {
      case "exit-status":
        this.#exitStatus = control.status;
        this.#emit({
          ...this.#snapshot,
          exitStatus: control.status,
        });
        return;
      case "error":
        if (control.code === "authorization-denied" || control.code === "session-denied") {
          this.#finish("denied", target);
        } else if (control.code === "protocol-error") {
          this.#finish("protocol-error", target);
        } else {
          this.#finish("internal-error", target);
        }
        return;
      case "close":
        this.#finish(closePhase(control.reason), target);
    }
  }

  #finish(phase: ConnectionPhase, target?: TargetPresentation): void {
    const retainedStatus = this.#exitStatus;
    const retainedTarget = target ?? currentTarget(this.#snapshot);
    this.#replaceConnection(false);
    this.#emit({
      phase,
      targets: this.#targets,
      ...(retainedTarget === undefined ? {} : {
        activeTarget: retainedTarget.name,
        readOnly: retainedTarget.readOnly,
      }),
      ...(retainedStatus === undefined ? {} : { exitStatus: retainedStatus }),
    });
  }

  #replaceConnection(orderly: boolean): number {
    this.#generation += 1;
    this.#inputDisposers.splice(0).forEach((dispose) => dispose());
    this.#resize?.dispose();
    this.#resize = undefined;
    this.#output?.dispose();
    this.#output = undefined;
    this.#clearConnectionTimer();
    const socket = this.#socket;
    this.#socket = undefined;
    if (socket !== undefined) {
      socket.onopen = null;
      socket.onmessage = null;
      socket.onclose = null;
      socket.onerror = null;
      if (orderly && socket.readyState === SOCKET_OPEN) {
        try {
          socket.send(encodeClientControl({ type: "close" }));
        } catch {
          // The connection is already being discarded.
        }
      }
      try {
        socket.close();
      } catch {
        // Teardown is idempotent and must not expose transport details.
      }
    }
    this.#exitStatus = undefined;
    return this.#generation;
  }

  #clearConnectionTimer(): void {
    if (this.#connectionTimer === undefined) return;
    this.#scheduler.clear(this.#connectionTimer);
    this.#connectionTimer = undefined;
  }

  #isCurrent(generation: number): boolean {
    return generation === this.#generation;
  }

  #emit(snapshot: ConnectionSnapshot): void {
    this.#snapshot = {
      ...snapshot,
      targets: snapshot.targets.map((target) => ({ ...target })),
    };
    this.#dependencies.onState(this.#snapshot);
  }
}

function apiPhase(error: unknown): ConnectionPhase {
  if (error instanceof FrontendApiError) return error.category;
  return "internal-error";
}

function closePhase(reason: CloseReason): ConnectionPhase {
  switch (reason) {
    case "client-request":
      return "user-closed";
    case "exited":
      return "exited";
    case "timeout":
      return "timed-out";
    case "policy":
      return "denied";
    case "protocol-error":
      return "protocol-error";
    case "transport-error":
      return "transport-disconnected";
    case "internal-error":
      return "internal-error";
  }
}

function currentTarget(snapshot: ConnectionSnapshot): TargetPresentation | undefined {
  if (snapshot.activeTarget === undefined || snapshot.readOnly === undefined) return undefined;
  return { name: snapshot.activeTarget, readOnly: snapshot.readOnly };
}
