// Imported by src/tests/package.ts with stdin left open and idle.
// It must print one line and exit on its own; nothing may read stdin or write JSON-RPC.
import { analyzeTool, VERSION } from "../../lib.js";

const r = analyzeTool({ name: "exec", description: "Execute arbitrary shell commands" });
console.log(JSON.stringify({ version: VERSION, risk: r.summary.overallRisk }));
