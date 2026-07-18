import {
  spawn,
  spawnSync,
  type ChildProcessWithoutNullStreams,
} from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const FRONTEND_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPOSITORY_DIR = resolve(FRONTEND_DIR, "..");
const PTY_FIXTURE = resolve(
  REPOSITORY_DIR,
  "crates/ttygated/tests/fixtures/pty_child.sh",
);
const CARGO = cargoExecutable();

export interface TestServer {
  origin: string;
  stop(): Promise<void>;
}

export async function startTestServer(): Promise<TestServer> {
  const port = await availablePort();
  const origin = `http://127.0.0.1:${port}`;
  const directory = await mkdtemp(join(tmpdir(), "ttygate-browser-"));
  const config = join(directory, "ttygate.toml");
  await writeFile(config, configuration(origin, port), { mode: 0o600 });
  const child = spawn(CARGO, ["run", "--quiet", "--bin", "ttygated", "--", config], {
    cwd: REPOSITORY_DIR,
    env: {
      ...process.env,
      PATH: `${dirname(CARGO)}:${process.env.PATH ?? ""}`,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (chunk: Buffer) => {
    output += chunk.toString("utf8");
  });
  child.stderr.on("data", (chunk: Buffer) => {
    output += chunk.toString("utf8");
  });
  try {
    await waitUntilHealthy(origin, child, () => output);
  } catch (error) {
    child.kill("SIGTERM");
    await exited(child);
    await rm(directory, { recursive: true, force: true });
    throw error;
  }

  return {
    origin,
    async stop() {
      child.kill("SIGTERM");
      await exited(child);
      await rm(directory, { recursive: true, force: true });
    },
  };
}

function configuration(origin: string, port: number): string {
  return `
[server]
bind = "127.0.0.1:${port}"
mode = "dev"
public_url = "${origin}"

[auth]
provider = "dev"
user = "browser-smoke"

[audit]
format = "json"
path = "./unused-browser-smoke-audit.jsonl"
recording = false

[limits]
max_sessions = 4
max_sessions_per_user = 4
idle_timeout_seconds = 30
absolute_timeout_seconds = 60

[[targets]]
name = "interactive"
type = "pty"
command = [${JSON.stringify(PTY_FIXTURE)}]
read_only = false

[[targets]]
name = "read-only"
type = "pty"
command = [${JSON.stringify(PTY_FIXTURE)}]
read_only = true
`;
}

async function availablePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolvePromise);
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no loopback port");
  await new Promise<void>((resolvePromise, reject) => {
    server.close((error) => error === undefined ? resolvePromise() : reject(error));
  });
  return address.port;
}

async function waitUntilHealthy(
  origin: string,
  child: ChildProcessWithoutNullStreams,
  output: () => string,
): Promise<void> {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`ttygated exited before health check: ${safeProcessOutput(output())}`);
    }
    try {
      const response = await fetch(`${origin}/healthz`);
      if (response.ok) return;
    } catch {
      // The listener is still starting.
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 50));
  }
  throw new Error(`ttygated health check timed out: ${safeProcessOutput(output())}`);
}

async function exited(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (child.exitCode !== null) return;
  await new Promise<void>((resolvePromise) => child.once("exit", () => resolvePromise()));
}

function safeProcessOutput(output: string): string {
  return output.slice(-2_000).replaceAll(/[\r\n]+/g, " ");
}

function cargoExecutable(): string {
  if (process.env.CARGO !== undefined) return process.env.CARGO;
  const rustup = spawnSync("rustup", ["which", "cargo"], { encoding: "utf8" });
  if (rustup.status === 0 && rustup.stdout.trim() !== "") return rustup.stdout.trim();
  return "cargo";
}
