import type {
  ConnectionPhase,
  ConnectionSnapshot,
} from "./connection.ts";

export type StatusTone = "pending" | "ready" | "active" | "error" | "closed";

export interface ViewModel {
  status: string;
  tone: StatusTone;
  actionLabel: string;
  actionDisabled: boolean;
  targetDisabled: boolean;
  readOnly: boolean;
}

export interface AppElements {
  target: HTMLSelectElement;
  action: HTMLButtonElement;
  status: HTMLElement;
  readOnlyBadge: HTMLElement;
  terminal: HTMLElement;
  shell: HTMLElement;
}

export function viewModel(snapshot: ConnectionSnapshot): ViewModel {
  const sessionPending = snapshot.phase === "requesting-authorization"
    || snapshot.phase === "connecting";
  const active = snapshot.phase === "active";
  const unavailable = snapshot.phase === "establishing-identity";
  return {
    status: statusCopy(snapshot),
    tone: statusTone(snapshot.phase),
    actionLabel: sessionPending
      ? "Cancel connection"
      : active
        ? "Close terminal"
        : "Connect terminal",
    actionDisabled: unavailable,
    targetDisabled: unavailable || sessionPending || active,
    readOnly: snapshot.readOnly === true,
  };
}

export function findAppElements(document: Document): AppElements {
  return {
    target: requiredElement(document, "target-select", HTMLSelectElement),
    action: requiredElement(document, "session-action", HTMLButtonElement),
    status: requiredElement(document, "connection-status", HTMLElement),
    readOnlyBadge: requiredElement(document, "read-only-badge", HTMLElement),
    terminal: requiredElement(document, "terminal", HTMLElement),
    shell: requiredElement(document, "terminal-shell", HTMLElement),
  };
}

export function renderSnapshot(elements: AppElements, snapshot: ConnectionSnapshot): void {
  const model = viewModel(snapshot);
  elements.status.textContent = model.status;
  elements.status.dataset.tone = model.tone;
  elements.action.textContent = model.actionLabel;
  elements.action.disabled = model.actionDisabled;
  elements.target.disabled = model.targetDisabled;
  elements.readOnlyBadge.hidden = !model.readOnly;
  elements.shell.setAttribute(
    "aria-busy",
    snapshot.phase === "requesting-authorization" || snapshot.phase === "connecting"
      ? "true"
      : "false",
  );
  updateTargets(elements.target, snapshot);
}

function updateTargets(select: HTMLSelectElement, snapshot: ConnectionSnapshot): void {
  const names = snapshot.targets.map((target) => target.name);
  const current = Array.from(select.options).map((option) => option.value);
  if (names.length === current.length && names.every((name, index) => name === current[index])) {
    return;
  }
  const selected = snapshot.activeTarget ?? select.value;
  const options = snapshot.targets.map((target) => {
    const option = select.ownerDocument.createElement("option");
    option.value = target.name;
    option.textContent = target.readOnly ? `${target.name} — read-only` : target.name;
    return option;
  });
  select.replaceChildren(...options);
  if (names.includes(selected)) select.value = selected;
}

function statusCopy(snapshot: ConnectionSnapshot): string {
  switch (snapshot.phase) {
    case "establishing-identity":
      return "Establishing browser identity…";
    case "ready":
      return "Ready. Choose a configured target.";
    case "requesting-authorization":
      return "Requesting terminal authorization…";
    case "connecting":
      return "Connecting to the terminal…";
    case "active":
      return snapshot.readOnly
        ? "Terminal connected in read-only mode."
        : "Terminal connected.";
    case "denied":
      return "Terminal access was denied by policy.";
    case "protocol-error":
      return "The terminal protocol failed safely.";
    case "internal-error":
      return "The terminal is unavailable because of an internal error.";
    case "timed-out":
      return "The terminal session timed out.";
    case "exited":
      return exitCopy(snapshot);
    case "transport-disconnected":
      return "The terminal transport disconnected.";
    case "user-closed":
      return "You closed the terminal session.";
  }
}

function exitCopy(snapshot: ConnectionSnapshot): string {
  switch (snapshot.exitStatus?.kind) {
    case "code":
      return `The terminal process exited with code ${snapshot.exitStatus.code}.`;
    case "signal":
      return `The terminal process exited after signal ${snapshot.exitStatus.signal}.`;
    case "unavailable":
      return "The terminal process exited; a portable status is unavailable.";
    case undefined:
      return "The terminal process exited.";
  }
}

function statusTone(phase: ConnectionPhase): StatusTone {
  switch (phase) {
    case "establishing-identity":
    case "requesting-authorization":
    case "connecting":
      return "pending";
    case "ready":
      return "ready";
    case "active":
      return "active";
    case "denied":
    case "protocol-error":
    case "internal-error":
    case "timed-out":
      return "error";
    case "exited":
    case "transport-disconnected":
    case "user-closed":
      return "closed";
  }
}

function requiredElement<T extends Element>(
  document: Document,
  id: string,
  constructor: { new(): T },
): T {
  const element = document.getElementById(id);
  if (!(element instanceof constructor)) throw new Error(`missing #${id}`);
  return element;
}
