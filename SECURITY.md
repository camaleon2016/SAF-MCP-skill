# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue for a vulnerability.

Include what you found, how to reproduce it, the version or commit, and the transport involved (stdio, MCP over HTTP, REST, or library). You can expect an acknowledgment within 5 business days and a status update within 14 business days. Fixes are released as a new version, followed by a GitHub Security Advisory crediting the reporter unless you prefer otherwise.

## Supported versions

| Version | Supported |
|---|---|
| 2.x | Yes |
| 1.x | No. Upgrade to 2.x; see the 2.0.0 security notes in [CHANGELOG.md](CHANGELOG.md) |

## Scope

In scope: the skill's own attack surface. That includes the REST and MCP HTTP servers, access control, discovery (which can start processes and make outbound requests), and anything that lets a caller act beyond the [Security Model](README.md#security-model).

Not vulnerabilities, but welcome as regular issues:

- A rule that misses an attack pattern, or flags something harmless
- Disagreement with a severity or a framework mapping
- Catalog content, which comes from upstream [SAF-MCP](https://github.com/safe-agentic-framework/safe-mcp); please propose catalog changes there

## Running it safely

The defaults are locked down: command discovery is off on the network servers, browsers and DNS rebinding are refused, and the servers will not listen beyond loopback without API keys. Turning any of that off is a deliberate choice; the README's Security Model section explains each setting and its risk.
