import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";

import { establishIdentity } from "./identity.ts";

await establishIdentity();

const root = document.getElementById("terminal");
if (root === null) {
  throw new Error("missing #terminal element");
}

const term = new Terminal();
term.open(root);
term.write("ttygate frontend scaffold\r\n");
