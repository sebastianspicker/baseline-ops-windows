// Keeps the static tour's profiles identical to their reviewed repository examples.
import { readFile, writeFile } from "node:fs/promises";
const root = new URL("../", import.meta.url);
const names = ["baseline-audit", "endpoint-health-check", "rapid-triage"];
const profiles = await Promise.all(
  names.map(async (name) =>
    JSON.parse(
      await readFile(new URL(`examples/profiles/${name}.json`, root), "utf8"),
    ),
  ),
);
const serialized = JSON.stringify(profiles, null, 2) + "\n";
const output = new URL("docs/demo/profiles.json", root);
const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && args[0] !== "--check")) {
  throw new Error("Usage: node tools/demo-profiles.mjs [--check]");
}
if (args[0] === "--check") {
  if ((await readFile(output, "utf8")) !== serialized) {
    throw new Error(
      "Demo profiles are stale. Run node tools/demo-profiles.mjs.",
    );
  }
  console.log("Demo profiles match all three source examples.");
} else {
  await writeFile(output, serialized);
  console.log("Updated docs/demo/profiles.json.");
}
