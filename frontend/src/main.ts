import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import "./app.css";

import { fetchTargets, requestSessionGrant } from "./api.ts";
import {
  TerminalConnectionController,
  type ConnectionSnapshot,
  type SocketPort,
  type TerminalPort,
} from "./connection.ts";
import { establishIdentity } from "./identity.ts";
import { findAppElements, renderSnapshot } from "./ui.ts";

const elements = findAppElements(document);
const terminal = new Terminal({
  allowProposedApi: false,
  cursorBlink: true,
  cursorStyle: "block",
  fontFamily: '"SFMono-Regular", Consolas, "Liberation Mono", monospace',
  fontSize: 14,
  lineHeight: 1.2,
  screenReaderMode: true,
  scrollback: 5_000,
  theme: {
    background: "#050706",
    foreground: "#e5ebe7",
    cursor: "#b7f34b",
    cursorAccent: "#11170d",
    selectionBackground: "#40512c",
  },
});
const fitAddon = new FitAddon();
terminal.loadAddon(fitAddon);
terminal.open(elements.terminal);

const terminalPort: TerminalPort = {
  write(data, drained) {
    terminal.write(data, drained);
  },
  onData(handler) {
    const disposable = terminal.onData(handler);
    return () => disposable.dispose();
  },
  onBinary(handler) {
    const disposable = terminal.onBinary(handler);
    return () => disposable.dispose();
  },
  onResize(handler) {
    const disposable = terminal.onResize(handler);
    return () => disposable.dispose();
  },
  size() {
    return { cols: terminal.cols, rows: terminal.rows };
  },
  focus() {
    terminal.focus();
  },
};

let latest: ConnectionSnapshot = {
  phase: "establishing-identity",
  targets: [],
};
const controller = new TerminalConnectionController({
  establishIdentity,
  fetchTargets,
  requestSessionGrant,
  createSocket: (url): SocketPort => new WebSocket(url),
  pageUrl: window.location.href,
  terminal: terminalPort,
  onState(snapshot) {
    latest = snapshot;
    renderSnapshot(elements, snapshot);
  },
});

elements.action.addEventListener("click", () => {
  if (
    latest.phase === "active"
    || latest.phase === "connecting"
    || latest.phase === "requesting-authorization"
  ) {
    controller.close();
  } else {
    void controller.connect(elements.target.value);
  }
});

let fitFrame = 0;
const fit = (): void => {
  window.cancelAnimationFrame(fitFrame);
  fitFrame = window.requestAnimationFrame(() => {
    try {
      fitAddon.fit();
    } catch {
      // A hidden or departing terminal has no measurable geometry.
    }
  });
};
const resizeObserver = new ResizeObserver(fit);
resizeObserver.observe(elements.terminal);
fit();

let disposed = false;
const dispose = (): void => {
  if (disposed) return;
  disposed = true;
  controller.close();
  resizeObserver.disconnect();
  window.cancelAnimationFrame(fitFrame);
  terminal.dispose();
};
window.addEventListener("pagehide", dispose, { once: true });
window.addEventListener("beforeunload", dispose, { once: true });

await controller.start();
