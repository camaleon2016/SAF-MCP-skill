# Examples

## risky-mcp-config.json

A deliberately risky MCP client config for demonstrating `analyze_config`. **Do not copy it into a real client config**, and keep it out of `.vscode/mcp.json`: VS Code offers to start the servers in that file, and these are risky on purpose. The token is a placeholder, not a real secret.

Ask your assistant, with the skill connected:

> Use saf-mcp to check examples/risky-mcp-config.json for security issues.

Expected findings (nothing is started):

| Rule | Severity | Finding |
|---|---|---|
| RULE-038 | High | `filesystem` runs an unpinned package; `github` runs an image with no fixed version; `sandbox` runs an image by a movable tag |
| RULE-039 | Critical | `sandbox` runs `--privileged` |
| RULE-040 | High | `GITHUB_PERSONAL_ACCESS_TOKEN` is in plaintext; only its first four characters are shown |

The pinned `fetch` server produces no finding.
