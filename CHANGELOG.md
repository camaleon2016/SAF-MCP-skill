# Changelog

All notable changes to this project are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [2.0.0] - Unreleased

Version 2.0.0 fixes serious issues in the skill's own security and brings its catalog in line with upstream SAF-MCP. Several defaults and outputs change, so read **Breaking changes** before upgrading.

### Security

- **Remote command execution through discovery (fixed).** In 1.x, `POST /v1/discover/stdio` and `/v1/discover/config` ran any command the caller sent, with authentication off by default. Command discovery is now off on the REST and MCP HTTP servers; enabling it requires API keys.
- **Browser driven attacks on a local server (fixed).** In 1.x, the REST server allowed any origin, accepted `text/plain` POST bodies, and did not check the `Host` header, so a web page could reach a server bound to `127.0.0.1`, including through DNS rebinding. Foreign origins and hosts are now refused, and POST bodies must be `application/json`.
- **IP allowlist bypass (fixed).** `X-Forwarded-For` was trusted from any client, CIDR entries never matched, and "required but empty" settings failed open. The header is now ignored unless `SAFE_MCP_TRUST_PROXY=true`, CIDR ranges work, and empty required settings stop startup.
- **SSRF through URL discovery (fixed).** Cloud metadata and link local addresses are always refused; private ranges are refused when the skill is exposed beyond loopback.
- **Dependencies.** Updated past GHSA-6qxp-vccf-f47h (`@modelcontextprotocol/sdk`) and GHSA-jqcg-44mw-7w3h (`proxy-addr`).
- **Agent prompt injection.** Discovery tools that start processes now carry `destructiveHint` annotations, so MCP clients ask before calling them.

### Breaking changes

- Command based discovery is off on the REST and MCP HTTP servers by default (`SAFE_MCP_ALLOW_COMMAND_DISCOVERY`).
- The servers refuse to start on a non loopback `HOST` without API keys (`SAFE_MCP_ALLOW_INSECURE_BIND` to override).
- REST POST requests must send `Content-Type: application/json`; requests with a foreign `Origin` or `Host` are refused.
- Import the library from the package root (`import { analyzeTool } from "safe-mcp-skill"`). `dist/index.js` is now only the `safe-mcp-skill` command and exports nothing.
- Severities follow upstream SAF-MCP: 26 techniques changed, 12 of them used by rules. `SAFE-T1001` stays Critical through a documented override.
- Five techniques use their upstream names (for example `SAFE-T1201` is now Post-Approval Tool Mutation); old names remain searchable as aliases.
- RULE-018 now reports `SAFE-T1302` (Agentic Confused Deputy), the upstream replacement for deprecated `SAFE-T1104`.
- `techniques.json` no longer carries a duplicate copy of the mitigations or their statistics. Framework totals count active techniques and mitigations.

### Added

- Catalog sync from a pinned upstream SAF-MCP commit (`npm run sync:catalog`), with a CI drift check and generated reports in `docs/`.
- `SAFE-T1112` Sampling Request Abuse, and mitigations `SAFE-M-69` through `SAFE-M-74`.
- Technique lifecycle (`deprecated`, `replacedBy`), aliases, and profiles; withdrawn mitigation IDs that resolve but are never recommended.
- `SAF-` IDs accepted everywhere, in any case.
- Severity overrides with required rationales (`scripts/severity-overrides.json`).
- `SKILL.md` for use as an Agent Skill, `SECURITY.md`, and this changelog.
- Test suites for the security model, catalog integrity, and packaging.

### Fixed

- Findings for 25 of 32 rules carried no mitigations. Every finding now includes mitigations, strongest first.
- Importing the library started the MCP stdio server, so a host program never exited and had its stdin and stdout taken over.
- README demo output and counts now match what the engine returns.
- The catalog check works on Windows checkouts with CRLF line endings.

## [1.0.0] - 2026-04-14

First release: the SAFE-MCP analysis engine with 32 rules, MCP (stdio and HTTP), REST, OpenAI function calling, and C# Semantic Kernel surfaces, auto discovery, and STRIDE, MITRE ATLAS, OWASP LLM Top 10, and NIST AI RMF mappings.

[2.0.0]: https://github.com/camaleon2016/SAFE-MCP-skill/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/camaleon2016/SAFE-MCP-skill/releases/tag/v1.0.0
