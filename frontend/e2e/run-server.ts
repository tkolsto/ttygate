import {
  spawn,
  spawnSync,
  type ChildProcess,
} from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
const PROCESS_EXIT_GRACE_MILLISECONDS = 2_000;

export interface FixtureProcessGroup {
  leader: number;
  descendants: readonly number[];
}

export interface TestServer {
  origin: string;
  stop(): Promise<void>;
}

export async function startTestServer(): Promise<TestServer> {
  const port = await availablePort();
  const origin = `http://127.0.0.1:${port}`;
  const directory = await mkdtemp(join(tmpdir(), "ttygate-browser-"));
  const config = join(directory, "ttygate.toml");
  const fixtureMarker = join(directory, "fixture-pids");
  await writeFile(config, configuration(origin, port, fixtureMarker), { mode: 0o600 });
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
    try {
      await stopTestProcess(child, []);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
    throw error;
  }

  return {
    origin,
    async stop() {
      let failure: unknown;
      try {
        await stopTestProcess(child, await readFixtureGroups(fixtureMarker));
      } catch (error) {
        failure = error;
      } finally {
        try {
          await cleanupFixtureGroups(await readFixtureGroups(fixtureMarker));
        } catch (error) {
          failure ??= error;
        }
        await rm(directory, { recursive: true, force: true });
      }
      if (failure !== undefined) throw failure;
    },
  };
}

export async function stopTestProcess(
  child: ChildProcess,
  fixtureGroups: readonly FixtureProcessGroup[],
  graceMilliseconds = PROCESS_EXIT_GRACE_MILLISECONDS,
): Promise<void> {
  let failure: unknown;
  try {
    await terminateBounded(child, graceMilliseconds);
  } catch (error) {
    failure = error;
  }
  try {
    await cleanupFixtureGroups(fixtureGroups, graceMilliseconds);
  } catch (error) {
    failure ??= error;
  }
  if (failure !== undefined) throw failure;
}

async function cleanupFixtureGroups(
  fixtureGroups: readonly FixtureProcessGroup[],
  graceMilliseconds = PROCESS_EXIT_GRACE_MILLISECONDS,
): Promise<void> {
  let failure: unknown;
  for (const group of fixtureGroups) {
    try {
      await cleanupFixtureGroup(group, graceMilliseconds);
    } catch (error) {
      failure ??= error;
    }
  }
  if (failure !== undefined) throw failure;
}

async function cleanupFixtureGroup(
  group: FixtureProcessGroup,
  graceMilliseconds: number,
): Promise<void> {
  const tracked = [group.leader, ...group.descendants];
  if (!tracked.some(processExists)) return;
  try {
    process.kill(-group.leader, "SIGKILL");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
  }
  for (const pid of tracked) {
    try {
      process.kill(pid, "SIGKILL");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
    }
  }
  await waitUntilAbsent(tracked, graceMilliseconds);
}

function configuration(origin: string, port: number, fixtureMarker: string): string {
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
command = [${JSON.stringify(PTY_FIXTURE)}, "browser-track", ${JSON.stringify(fixtureMarker)}]
read_only = false

[[targets]]
name = "read-only"
type = "pty"
command = [${JSON.stringify(PTY_FIXTURE)}, "browser-track", ${JSON.stringify(fixtureMarker)}]
read_only = true
`;
}

async function readFixtureGroups(marker: string): Promise<FixtureProcessGroup[]> {
  let contents: string;
  try {
    contents = await readFile(marker, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
  return contents
    .split(/\r?\n/)
    .filter((line) => line.trim() !== "")
    .map((line) => {
      const [leader, descendant, ...extra] = line.trim().split(/\s+/);
      if (leader === undefined || descendant === undefined || extra.length !== 0) {
        throw new Error("browser fixture PID marker is malformed");
      }
      return {
        leader: Number.parseInt(leader, 10),
        descendants: [Number.parseInt(descendant, 10)],
      };
    });
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
  child: ChildProcess,
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

async function terminateBounded(
  child: ChildProcess,
  graceMilliseconds: number,
): Promise<void> {
  if (hasExited(child)) return;
  child.kill("SIGTERM");
  if (await exitsWithin(child, graceMilliseconds)) return;
  child.kill("SIGKILL");
  if (!await exitsWithin(child, graceMilliseconds)) {
    throw new Error("ttygated did not exit after SIGKILL");
  }
}

async function exitsWithin(child: ChildProcess, milliseconds: number): Promise<boolean> {
  if (hasExited(child)) return true;
  return await new Promise((resolvePromise) => {
    const onExit = (): void => {
      clearTimeout(timer);
      resolvePromise(true);
    };
    const timer = setTimeout(() => {
      child.off("exit", onExit);
      resolvePromise(hasExited(child));
    }, milliseconds);
    child.once("exit", onExit);
  });
}

function hasExited(child: ChildProcess): boolean {
  return child.exitCode !== null || child.signalCode !== null;
}

async function waitUntilAbsent(pids: readonly number[], milliseconds: number): Promise<void> {
  const deadline = Date.now() + milliseconds;
  while (pids.some(processExists)) {
    if (Date.now() >= deadline) {
      throw new Error("browser fixture process survived teardown");
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 20));
  }
}

function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
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
