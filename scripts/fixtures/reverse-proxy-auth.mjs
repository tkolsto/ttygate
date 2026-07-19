import { createServer } from "node:http";
import { pathToFileURL } from "node:url";

export const FIXTURE_AUTHORIZATION = "Bearer chunk42-fixture-only";
export const FIXTURE_IDENTITY = "synthetic-user";

export function authorize(method, path, authorization) {
  if (path !== "/verify") return { status: 404, identity: undefined };
  if (method !== "GET") return { status: 405, identity: undefined };
  if (
    typeof authorization !== "string" ||
    authorization.length > 256 ||
    authorization !== FIXTURE_AUTHORIZATION
  ) {
    return { status: 401, identity: undefined };
  }
  return { status: 204, identity: FIXTURE_IDENTITY };
}

export function startAuthServer() {
  const server = createServer((request, response) => {
    const distinctAuthorization = request.headersDistinct?.authorization;
    const authorization = Array.isArray(distinctAuthorization)
      ? distinctAuthorization.length === 1
        ? distinctAuthorization[0]
        : undefined
      : request.headers.authorization;
    const decision = authorize(
      request.method ?? "",
      request.url ?? "",
      authorization,
    );
    request.resume();
    response.setHeader("Cache-Control", "no-store");
    if (decision.identity !== undefined) {
      response.setHeader("X-Authenticated-User", decision.identity);
    }
    response.writeHead(decision.status);
    response.end();
  });
  server.maxHeadersCount = 64;
  server.headersTimeout = 5_000;
  server.requestTimeout = 5_000;
  server.listen(9000, "0.0.0.0", () => {
    process.stdout.write("AUTH_READY\n");
  });
  const stop = () => server.close(() => process.exit(0));
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
  return server;
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  startAuthServer();
}
