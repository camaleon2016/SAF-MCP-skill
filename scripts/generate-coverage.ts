/**
 * Write docs/coverage.md from the rules and the synced catalog.
 *
 *   npx tsx scripts/generate-coverage.ts           (write)
 *   npx tsx scripts/generate-coverage.ts --check   (fail if out of date; npm test also checks)
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { renderCoverageMarkdown } from "../src/engine/coverage.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(ROOT, "docs", "coverage.md");
const { commit } = JSON.parse(readFileSync(join(ROOT, "scripts", "upstream.json"), "utf-8")) as { commit: string };
const doc = renderCoverageMarkdown(commit);
const current = existsSync(OUT) ? readFileSync(OUT, "utf-8").replace(/\r\n/g, "\n") : "";

if (process.argv.includes("--check")) {
  if (current !== doc) {
    console.error("docs/coverage.md is out of date. Run: npx tsx scripts/generate-coverage.ts");
    process.exit(1);
  }
  console.log("docs/coverage.md is current.");
} else {
  writeFileSync(OUT, doc);
  console.log("Wrote docs/coverage.md");
}
