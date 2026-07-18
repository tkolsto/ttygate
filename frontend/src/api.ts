export type ApiErrorCategory = "denied" | "timed-out" | "internal-error";

export interface TargetPresentation {
  name: string;
  readOnly: boolean;
}

export interface SessionGrant {
  ticket: string;
  target: TargetPresentation;
}

export class FrontendApiError extends Error {
  readonly category: ApiErrorCategory;

  constructor(category: ApiErrorCategory) {
    super("The terminal request could not be completed.");
    this.name = "FrontendApiError";
    this.category = category;
  }
}

export async function fetchTargets(request: typeof fetch = fetch): Promise<TargetPresentation[]> {
  const response = await safeRequest(request, "/api/targets", {
    method: "POST",
    credentials: "same-origin",
  });
  if (!response.ok) throw classifiedError(response.status);
  const value = await safeJson(response);
  if (!isRecord(value) || !hasExactKeys(value, ["targets"]) || !Array.isArray(value.targets)) {
    throw new FrontendApiError("internal-error");
  }
  return value.targets.map(parseTarget);
}

export async function requestSessionGrant(
  target: string,
  request: typeof fetch = fetch,
): Promise<SessionGrant> {
  if (!isTargetName(target)) throw new FrontendApiError("internal-error");
  const response = await safeRequest(request, "/api/sessions", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target }),
  });
  if (!response.ok) throw classifiedError(response.status);
  const value = await safeJson(response);
  if (
    !isRecord(value)
    || !hasExactKeys(value, ["ticket", "target"])
    || typeof value.ticket !== "string"
    || !/^[A-Za-z0-9_-]{1,1024}$/.test(value.ticket)
  ) {
    throw new FrontendApiError("internal-error");
  }
  return {
    ticket: value.ticket,
    target: parseTarget(value.target),
  };
}

async function safeRequest(
  request: typeof fetch,
  input: RequestInfo | URL,
  init: RequestInit,
): Promise<Response> {
  try {
    return await request(input, init);
  } catch {
    throw new FrontendApiError("internal-error");
  }
}

async function safeJson(response: Response): Promise<unknown> {
  try {
    return await response.json() as unknown;
  } catch {
    throw new FrontendApiError("internal-error");
  }
}

function classifiedError(status: number): FrontendApiError {
  if ([401, 403, 404].includes(status)) return new FrontendApiError("denied");
  if ([408, 504].includes(status)) return new FrontendApiError("timed-out");
  return new FrontendApiError("internal-error");
}

function parseTarget(value: unknown): TargetPresentation {
  if (
    !isRecord(value)
    || !hasExactKeys(value, ["name", "readOnly"])
    || !isTargetName(value.name)
    || typeof value.readOnly !== "boolean"
  ) {
    throw new FrontendApiError("internal-error");
  }
  return { name: value.name, readOnly: value.readOnly };
}

function isTargetName(value: unknown): value is string {
  return typeof value === "string"
    && /^[A-Za-z0-9._][A-Za-z0-9._-]{0,127}$/.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
