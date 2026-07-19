# ttygate WebSocket Wire Protocol

## Scope

This document is the authoritative contract for terminal traffic between the ttygate backend and frontend. It specifies WebSocket payloads only. Authentication, Origin validation, ticket issuance, ticket redemption, session creation, PTY/SSH execution, and browser connection management are outside the codec.

The WebSocket bridge MUST complete the authenticated, single-use ticket redemption flow before accepting terminal traffic. Tickets, secrets, and session identifiers MUST NOT appear in WebSocket URLs or protocol messages defined here.

## Pre-protocol authentication envelope

After the HTTP upgrade has passed Origin and browser-session-cookie authentication, the client MUST send exactly one complete text message before any terminal protocol traffic:

```json
{"ticket":"<opaque-ticket>"}
```

This envelope is not a versioned terminal control message and is not accepted after authentication. It is a closed schema: `ticket` is the only field and is required exactly once. The bridge applies a short deadline and a 256-byte UTF-8 bound before parsing. Empty, binary, malformed, duplicate-key, missing-field, unknown-field, wrong-type, and oversized handshakes fail closed without starting a child. The WebSocket transport reassembles frames into one bounded message; the bridge never parses partial fragments.

The ticket is a secret bearer value. Implementations MUST NOT place it in the WebSocket URL, path, query, headers, subprotocol, errors, lifecycle events, or logs, and MUST NOT reflect the raw envelope. The bridge first authenticates the cookie-bound identity and then atomically redeems the ticket against that identity. Successful redemption is single use and yields the server-configured target authority used to create the session.

## Versioning and compatibility

The current protocol version is the JSON integer `1`. Every control message MUST contain `"version":1` and a `type` discriminator. Binary frames inherit the version established by the surrounding bridge and carry no header.

Version matching is exact. A decoder MUST reject any control message whose version is missing, is not an integer, or is not `1`. A future incompatible protocol version will use a new explicit decoder; implementations MUST NOT guess at or silently accept unknown versions. Unknown fields and message types are not extension points and MUST be rejected.

## WebSocket framing

WebSocket binary messages contain opaque terminal bytes:

| Direction | Meaning |
|---|---|
| Client → server | terminal input |
| Server → client | terminal output |

Empty binary messages are valid. A binary message MUST be no larger than 65,536 bytes. Codecs MUST enforce the bound before copying or allocating based on attacker-controlled data. Terminal bytes MUST NOT be decoded as JSON, UTF-8, or HTML.

WebSocket text messages contain UTF-8 JSON control objects. Their encoded UTF-8 representation MUST be no larger than 4,096 bytes, checked before JSON parsing. Fragment reassembly and the WebSocket-level message limit belong to the bridge; the codec receives one complete message and applies the same limit again.

## Control messages

All objects are closed schemas: only the listed fields are allowed, all listed fields are required unless explicitly marked optional, and duplicate JSON object keys are invalid. Integers are JSON numbers with no fractional component.

### Client to server

Resize requests update the PTY dimensions:

```json
{"version":1,"type":"resize","cols":80,"rows":24}
```

`cols` and `rows` are integers from 1 through 4,096 inclusive.

A client close requests orderly session termination:

```json
{"version":1,"type":"close"}
```

Receiving `close` is idempotent at the session boundary. It does not encode a client-supplied reason. The server eventually reports its terminal `close` state or the transport closes.

### Server to client

An exit-status reports the child outcome. Exactly one tagged status form is present:

```json
{"version":1,"type":"exit-status","status":{"kind":"code","code":0}}
{"version":1,"type":"exit-status","status":{"kind":"signal","signal":15}}
{"version":1,"type":"exit-status","status":{"kind":"unavailable"}}
```

An ordinary `code` is an integer from 0 through 255. A `signal` is an integer from 1 through 127. `unavailable` means the bridge cannot provide a portable child outcome; it MUST NOT be replaced by an invented numeric code.

An error reports a safe user-facing failure with a stable machine-readable code:

```json
{"version":1,"type":"error","code":"session-unavailable","message":"The terminal session is unavailable."}
```

SSH setup failures use this fixed, closed mapping:

| Code | Curated message |
|---|---|
| `ssh-host-key-failed` | `The SSH host identity could not be verified.` |
| `ssh-connection-failed` | `The SSH connection could not be established.` |
| `ssh-authentication-failed` | `SSH authentication was rejected.` |
| `ssh-policy-denied` | `SSH access was denied by policy.` |
| `ssh-failed` | `The SSH session could not be established safely.` |

Unknown and mismatched host keys intentionally share `ssh-host-key-failed`.
These codes contain no target name, host, username, configured path, argv,
OpenSSH diagnostic, terminal data, or secret. SSH targets add no client
authority fields: after ticket redemption, the server resolves all SSH
authority from the ticket-bound configured target and authenticated identity.

`code` is 1–64 ASCII characters, begins with a lowercase letter, and otherwise contains lowercase letters, digits, or single hyphens (no leading, trailing, or adjacent hyphens). `message` is 1–256 Unicode scalar values, contains no ASCII control characters, and is plain text only. Producers MUST use curated text and MUST NOT include hostile payloads, secrets, terminal data, raw parser errors, or HTML. Consumers MUST render it as text, never HTML.

A server close is the final typed lifecycle notification:

```json
{"version":1,"type":"close","reason":"client-request"}
```

`reason` is one of `client-request`, `exited`, `timeout`, `policy`, `protocol-error`, `transport-error`, or `internal-error`. It is intentionally finite so the frontend can select a stable state without displaying arbitrary backend detail. `exit-status`, when available, precedes `close` with reason `exited`.

## Validation and limits

| Item | Limit or rule |
|---|---|
| Protocol version | exactly integer `1` |
| Text message | at most 4,096 UTF-8 bytes |
| Binary message | at most 65,536 bytes |
| Columns and rows | integer 1–4,096 |
| Exit code | integer 0–255 |
| Signal number | integer 1–127 |
| Error code | constrained ASCII token, 1–64 bytes |
| Error message | 1–256 Unicode scalar values; no ASCII controls |

Malformed JSON, invalid UTF-8 at a byte-oriented text boundary, non-object JSON, duplicate keys, missing fields, unknown fields, unknown types, wrong field types, fractional integers, invalid ranges, invalid direction-specific messages, and unsupported versions are protocol errors. Parsers MUST return typed errors suitable for logging and control flow without returning or embedding the hostile input.

## Protocol errors and close semantics

A protocol error is fatal to the connection because continuing after the peers disagree about framing or message meaning could reinterpret terminal input as control data. The bridge SHOULD send a curated generic `error` with code `protocol-error` only when the connection is still writable, then close using WebSocket close code 1008 (policy violation). It MUST NOT reflect the offending payload or raw parser error.

Oversized messages are fatal and SHOULD be rejected as early as the WebSocket library permits, using close code 1009 (message too big). Invalid UTF-8 in a WebSocket text message is normally rejected by the WebSocket implementation with code 1007; a byte-oriented codec boundary reports the same condition as a typed malformed-text error.

Transport loss ends the v0.1 session. There is no re-attach, replay, or resumable buffering. A client request or server notification does not replace the WebSocket close handshake; the bridge remains responsible for terminating the child and closing the transport.

## Backpressure

The codecs are pure and do not buffer streams. Runtime producers and consumers MUST be joined by bounded queues with explicit capacity. When a queue is full, the producer MUST pause or apply upstream backpressure rather than grow memory without bound or discard unreported terminal data. Cancellation and session teardown MUST remain selectable while a task is waiting for queue capacity.

The 65,536-byte binary message limit is a per-message safety bound, not permission to accumulate an unbounded number of messages. Chunk 1.4 owns bounded PTY output and Chunk 1.5 owns bounded WebSocket bridging.
