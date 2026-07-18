import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import test from "node:test";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { stopTestProcess } from "./run-server.ts";

const FRONTEND_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE = resolve(
  FRONTEND_DIR,
  "../crates/ttygated/tests/fixtures/pty_child.sh",
);

test("browser server stop is bounded and reaps an active fixture process group", async () => {
  const child = spawn(FIXTURE, ["ignore-hup"], {
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let leader = child.pid;
  let descendant: number | undefined;
  try {
    const pids = await fixturePids(child.stdout);
    leader = pids.leader;
    descendant = pids.descendant;

    await Promise.race([
      stopTestProcess(child, [{
        leader,
        descendants: [descendant],
      }], 100),
      new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error("browser server teardown was not bounded")), 2_000);
      }),
    ]);

    assert.equal(processExists(leader), false);
    assert.equal(processExists(descendant), false);
  } finally {
    if (leader !== undefined) {
      try {
        process.kill(-leader, "SIGKILL");
      } catch {
        // The process group is already gone.
      }
    }
  }
});

test("fixture cleanup runs even when daemon termination fails", async () => {
  const child = spawn(FIXTURE, ["ignore-hup"], {
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let leader = child.pid;
  let descendant: number | undefined;
  try {
    const pids = await fixturePids(child.stdout);
    leader = pids.leader;
    descendant = pids.descendant;
    const daemon = new NonExitingChild() as unknown as ChildProcess;

    await assert.rejects(
      stopTestProcess(daemon, [{
        leader,
        descendants: [descendant],
      }], 20),
      /did not exit/,
    );

    assert.equal(processExists(leader), false);
    assert.equal(processExists(descendant), false);
  } finally {
    if (leader !== undefined) {
      try {
        process.kill(-leader, "SIGKILL");
      } catch {
        // The process group is already gone.
      }
    }
  }
});

test("browser fixture records process IDs before READY output is consumed", async () => {
  const directory = await mkdtemp(join(tmpdir(), "ttygate-runner-unit-"));
  const marker = join(directory, "fixture-pids");
  const child = spawn(FIXTURE, ["browser-track", marker], {
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const leader = child.pid;
  try {
    const pids = await markerPids(marker);
    assert.equal(pids.leader, leader);
    assert.equal(processExists(pids.descendant), true);
  } finally {
    if (leader !== undefined) {
      try {
        process.kill(-leader, "SIGKILL");
      } catch {
        // The process group is already gone.
      }
    }
    await rm(directory, { recursive: true, force: true });
  }
});

class NonExitingChild extends EventEmitter {
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;

  kill(): boolean {
    return false;
  }
}

async function fixturePids(
  output: NodeJS.ReadableStream,
): Promise<{ leader: number; descendant: number }> {
  return await new Promise((resolvePromise, reject) => {
    let text = "";
    const timer = setTimeout(() => reject(new Error("fixture PID output timed out")), 2_000);
    output.on("data", (chunk: Buffer) => {
      text += chunk.toString("utf8");
      const leader = /PID:(\d+)/.exec(text)?.[1];
      const descendant = /DESC:(\d+)/.exec(text)?.[1];
      if (leader !== undefined && descendant !== undefined) {
        clearTimeout(timer);
        resolvePromise({
          leader: Number.parseInt(leader, 10),
          descendant: Number.parseInt(descendant, 10),
        });
      }
    });
  });
}

function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

async function markerPids(
  marker: string,
): Promise<{ leader: number; descendant: number }> {
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    try {
      const [leader, descendant] = (await readFile(marker, "utf8")).trim().split(/\s+/);
      if (leader !== undefined && descendant !== undefined) {
        return {
          leader: Number.parseInt(leader, 10),
          descendant: Number.parseInt(descendant, 10),
        };
      }
    } catch {
      // The fixture has not written its runner-owned marker yet.
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 20));
  }
  throw new Error("fixture PID marker timed out");
}
