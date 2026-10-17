#!/usr/bin/env node
/**
 * The `safe-mcp-skill` command: runs the MCP server over stdio.
 *
 * This file starts a server as soon as it loads, so it is not the library
 * entry point. Import from "safe-mcp-skill" (src/lib.ts) instead.
 */
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { server } from "./server.js";

const transport = new StdioServerTransport();
await server.connect(transport);
