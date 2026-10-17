# Changelog

All notable changes to this project are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [2.2.0] - 2026-10-17

Renamed to match upstream. SAFE-MCP is now SAF-MCP (Secure Agentic Framework), and this project follows: the repository is SAF-MCP-skill, and the package and command are `saf-mcp-skill`. Nothing breaks for existing users.

### Changed

- The package and command are renamed from `SAF-MCP-skill` to `saf-mcp-skill`, and the MCP server reports itself as `saf-mcp-skill`. The repository is renamed to SAF-MCP-skill; GitHub redirects old links.
- Settings use the `SAF_MCP_` prefix. The old `SAFE_MCP_` prefix still works and logs a one time deprecation warning. When both are set, `SAF_MCP_` wins.
- Documentation, tool descriptions, and the catalog's framework name say SAF-MCP.
- The Agent Skill is now named `saf-mcp-security-analysis`.

### Compatibility

- Technique and mitigation IDs keep the `SAFE-` form in results. Lookups accept both `SAF-` and `SAFE-`.
- The C# plugin keeps its class and namespace names.
- MCP client configs that point at `dist/index.js` keep working. Renaming the server's label in your config is optional.

[2.2.0]: https://github.com/camaleon2016/SAF-MCP-skill/compare/v2.1.0...v2.2.0

## [2.1.0] - 2026-10-16

Detection quality. Tool poisoning and schema poisoning detection is rebuilt, keyword rules stop matching parts of words, and RULE-002 reports the right technique. Findings change for many inputs: fewer false alarms, more real attacks caught.

### Changed

- **RULE-001 and RULE-025 use a new detector** (`src/engine/detect.ts`). It decodes hidden text (Unicode tag characters, base64), strips invisible characters, folds lookalike letters and leetspeak, splits identifiers into words, and scans the tool name, description, annotations, and every schema string, including defaults, enum values, and property names.
- **RULE-002 reports SAFE-T1005 Exposed Endpoint Exploit** instead of SAFE-T1002 Supply Chain Compromise. It no longer flags stdio servers, which have no network listener, and leaves servers with exposed endpoints to RULE-003, so the same server is not reported twice.
- **Keyword rules match whole words.** For example RULE-006 no longer treats "Execute SQL" or "recommended" as shell access, RULE-013 no longer reads "capital" as "api", and RULE-018 no longer treats "root cause" as root access.
- **RULE-027 fires only for references to the model's own prompt or instructions**, not for any mention of "instructions", "policy", or "rules".
- RULE-006 now also catches tools that start processes ("starts the given command as a child process").
- Evidence names each signal, where it was found, and the matched text, instead of printing regular expressions.

### Added

- `confidence` ("high" or "medium") on RULE-001 and RULE-025 findings.
- Hostile input checks: the detector is bounded against input crafted to make patterns backtrack (a server controls the text it scans), and the suite times seven such inputs. CI jobs now time out after 15 minutes.
- A labeled detection corpus and suite (`npm run test:detection`) covering hidden markup, ASCII smuggling, homoglyphs, leetspeak, base64 payloads, markdown image exfiltration, task hijacking, concealment, approval bypass, and schema poisoning, plus harmless tools that resemble each. Known limits are recorded in the corpus and the README's Detection section.

### Fixed

- Missed attacks, including the widely documented hidden `<IMPORTANT>` instruction pattern, instructions hidden in Unicode tag characters, and poisoned parameter descriptions, defaults, and names.
- False alarms on ordinary phrasing such as "act as a concise editor", "file system: free space", "instructions for attendees", and "do not show passwords in the output".

## [2.0.0] - 2026-10-16

Version 2.0.0 fixes serious issues in the skill's own security and brings its catalog in line with upstream SAF-MCP. Several defaults and outputs change, so read **Breaking changes** before upgrading.

### Security

- - See [GHSA-jf24-ghv2-73gg](https://github.com/camaleon2016/SAF-MCP-skill/security/advisories/GHSA-jf24-ghv2-73gg) for the command execution issue fixed in this release.
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
- Import the library from the package root (`import { analyzeTool } from "SAF-MCP-skill"`). `dist/index.js` is now only the `SAF-MCP-skill` command and exports nothing.
- Severities follow upstream SAF-MCP: 27 techniques changed, 13 of them used by rules (for example `SAFE-T1001` Tool Poisoning is now High). Deliberate departures can be recorded in `scripts/severity-overrides.json` with a rationale; none are set in this release.
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

[2.1.0]: https://github.com/camaleon2016/SAF-MCP-skill/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/camaleon2016/SAF-MCP-skill/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/camaleon2016/SAF-MCP-skill/releases/tag/v1.0.0
