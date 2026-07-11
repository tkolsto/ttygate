import { build } from "esbuild";
import { cpSync } from "node:fs";

await build({
  entryPoints: ["src/main.ts"],
  bundle: true,
  minify: true,
  format: "esm",
  outfile: "dist/app.js",
});

cpSync("src/index.html", "dist/index.html");
