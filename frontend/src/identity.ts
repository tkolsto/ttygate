export class IdentityBootstrapError extends Error {
  constructor() {
    super("Development identity is unavailable.");
    this.name = "IdentityBootstrapError";
  }
}

export async function establishIdentity(request: typeof fetch = fetch): Promise<void> {
  let response: Response;
  try {
    response = await request("/api/identity", {
      method: "POST",
      credentials: "same-origin",
    });
  } catch {
    throw new IdentityBootstrapError();
  }
  if (!response.ok) {
    throw new IdentityBootstrapError();
  }
}
