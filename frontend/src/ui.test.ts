import assert from "node:assert/strict";
import test from "node:test";

import type { ConnectionPhase, ConnectionSnapshot } from "./connection.ts";
import { viewModel } from "./ui.ts";

function snapshot(
  phase: ConnectionPhase,
  extras: Partial<ConnectionSnapshot> = {},
): ConnectionSnapshot {
  return {
    phase,
    targets: [{ name: "shell", readOnly: false }],
    ...extras,
  };
}

test("view model provides stable accessible copy for every connection phase", () => {
  const expected: Record<ConnectionPhase, string> = {
    "establishing-identity": "Establishing browser identity…",
    "ready": "Ready. Choose a configured target.",
    "requesting-authorization": "Requesting terminal authorization…",
    "connecting": "Connecting to the terminal…",
    "active": "Terminal connected.",
    "denied": "Terminal access was denied by policy.",
    "ssh-host-key-failed": "SSH host identity verification failed.",
    "ssh-connection-failed": "The SSH connection could not be established.",
    "ssh-authentication-failed": "SSH authentication was rejected.",
    "ssh-policy-denied": "SSH access was denied by policy.",
    "ssh-failed": "The SSH session could not be established safely.",
    "protocol-error": "The terminal protocol failed safely.",
    "internal-error": "The terminal is unavailable because of an internal error.",
    "timed-out": "The terminal session timed out.",
    "exited": "The terminal process exited.",
    "transport-disconnected": "The terminal transport disconnected.",
    "user-closed": "You closed the terminal session.",
  };

  for (const [phase, status] of Object.entries(expected) as Array<[ConnectionPhase, string]>) {
    assert.equal(viewModel(snapshot(phase)).status, status);
  }
});

test("view model distinguishes read-only active sessions and portable exit statuses", () => {
  assert.deepEqual(
    viewModel(snapshot("active", {
      activeTarget: "readonly",
      readOnly: true,
    })),
    {
      status: "Terminal connected in read-only mode.",
      tone: "active",
      actionLabel: "Close terminal",
      actionDisabled: false,
      targetDisabled: true,
      readOnly: true,
    },
  );
  assert.equal(
    viewModel(snapshot("exited", { exitStatus: { kind: "code", code: 23 } })).status,
    "The terminal process exited with code 23.",
  );
  assert.equal(
    viewModel(snapshot("exited", { exitStatus: { kind: "signal", signal: 9 } })).status,
    "The terminal process exited after signal 9.",
  );
  assert.equal(
    viewModel(snapshot("exited", { exitStatus: { kind: "unavailable" } })).status,
    "The terminal process exited; a portable status is unavailable.",
  );
});

test("view model enables only valid target and session actions", () => {
  assert.deepEqual(
    viewModel(snapshot("establishing-identity")),
    {
      status: "Establishing browser identity…",
      tone: "pending",
      actionLabel: "Connect terminal",
      actionDisabled: true,
      targetDisabled: true,
      readOnly: false,
    },
  );
  assert.equal(viewModel(snapshot("ready")).actionDisabled, false);
  assert.equal(viewModel(snapshot("ready")).targetDisabled, false);
  assert.equal(viewModel(snapshot("requesting-authorization")).actionLabel, "Cancel connection");
  assert.equal(viewModel(snapshot("connecting")).actionLabel, "Cancel connection");
  assert.equal(viewModel(snapshot("active")).actionLabel, "Close terminal");
  assert.equal(viewModel(snapshot("denied")).actionLabel, "Connect terminal");
  assert.equal(viewModel(snapshot("denied")).targetDisabled, false);
  const bootstrapFailure = viewModel({
    phase: "internal-error",
    targets: [],
  });
  assert.equal(bootstrapFailure.actionDisabled, true);
  assert.equal(bootstrapFailure.targetDisabled, true);
});

test("view copy never includes target names or other server-controlled text", () => {
  const hostile = "<img src=x onerror=credential>";
  const model = viewModel({
    phase: "internal-error",
    targets: [{ name: hostile, readOnly: false }],
    activeTarget: hostile,
    readOnly: false,
  });

  assert.ok(!JSON.stringify(model).includes(hostile));
  assert.ok(!JSON.stringify(model).includes("credential"));
});

test("ssh_frontend_errors_never_reflect_target_host_user_path_argv_or_diagnostics", () => {
  const sentinels = [
    "target-secret",
    "ssh.example.test",
    "remote-user",
    "/run/ttygate/id-secret",
    "-oProxyCommand=credential",
    "REMOTE HOST IDENTIFICATION HAS CHANGED",
  ];
  const expected: Record<ConnectionPhase, string> = {
    "establishing-identity": "Establishing browser identity…",
    "ready": "Ready. Choose a configured target.",
    "requesting-authorization": "Requesting terminal authorization…",
    "connecting": "Connecting to the terminal…",
    "active": "Terminal connected.",
    "denied": "Terminal access was denied by policy.",
    "protocol-error": "The terminal protocol failed safely.",
    "internal-error": "The terminal is unavailable because of an internal error.",
    "timed-out": "The terminal session timed out.",
    "exited": "The terminal process exited.",
    "transport-disconnected": "The terminal transport disconnected.",
    "user-closed": "You closed the terminal session.",
    "ssh-host-key-failed": "SSH host identity verification failed.",
    "ssh-connection-failed": "The SSH connection could not be established.",
    "ssh-authentication-failed": "SSH authentication was rejected.",
    "ssh-policy-denied": "SSH access was denied by policy.",
    "ssh-failed": "The SSH session could not be established safely.",
  };

  for (const phase of [
    "ssh-host-key-failed",
    "ssh-connection-failed",
    "ssh-authentication-failed",
    "ssh-policy-denied",
    "ssh-failed",
  ] as const) {
    const model = viewModel({
      phase,
      targets: [{ name: sentinels.join(" "), readOnly: false }],
      activeTarget: sentinels.join(" "),
      readOnly: false,
    });
    assert.equal(model.status, expected[phase]);
    for (const sentinel of sentinels) {
      assert.ok(!JSON.stringify(model).includes(sentinel));
    }
  }
});
