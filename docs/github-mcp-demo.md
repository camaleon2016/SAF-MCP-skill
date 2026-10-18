# Quick Demo — Scanning the GitHub MCP Server

Point SAF-MCP at the real [GitHub MCP Server](https://github.com/github/github-mcp-server) and get a full security analysis in one command. No tool definitions to write — the skill auto-discovers everything.

## Prerequisites

| Tool | Why |
|---|---|
| Node.js 20+ | Runs SAF-MCP |
| Docker | Runs the GitHub MCP Server (no Go toolchain needed) |
| GitHub PAT | The GitHub MCP Server needs a token to start ([create one here](https://github.com/settings/personal-access-tokens/new)) |

> The PAT only needs read-only repo access — it's used by the target server, not by SAF-MCP itself. SAF-MCP just connects, lists tools, and analyzes their definitions.

## Setup (one time)

```bash
# 1. Build SAF-MCP
cd saf-mcp-skill
npm install
npm run build

# 2. Pull the GitHub MCP Server image
docker pull ghcr.io/github/github-mcp-server

# 3. Export your GitHub PAT
export GITHUB_PERSONAL_ACCESS_TOKEN="ghp_your_token_here"
```

<details>
<summary>Windows alternatives</summary>

**PowerShell:**
```powershell
cd C:\path\to\saf-mcp-skill
npm install
npm run build

docker pull ghcr.io/github/github-mcp-server

$env:GITHUB_PERSONAL_ACCESS_TOKEN = "ghp_your_token_here"
```

**CMD:**
```cmd
cd C:\path\to\saf-mcp-skill
npm install
npm run build

docker pull ghcr.io/github/github-mcp-server

set GITHUB_PERSONAL_ACCESS_TOKEN=ghp_your_token_here
```

</details>

## Run the Demo

### Step 1 — Start the SAF-MCP REST server

```bash
export SAF_MCP_API_KEYS="$(openssl rand -hex 24)"
SAF_MCP_ALLOW_COMMAND_DISCOVERY=true SAF_MCP_REQUIRE_API_KEY=true npm run start:rest
```

> This demo uses stdio discovery, which starts a process (here, a Docker container) on your machine, so it is off on the REST server unless you enable it with an API key. See [Security Model](../README.md#security-model). Keep the key exported in the terminal you send requests from.

You should see:

```
SAF-MCP REST API listening on http://127.0.0.1:3002
```

Leave this running and open a **second terminal** for the remaining steps.

### Step 2 — Discover & analyze the GitHub MCP Server (stdio)

This single command starts the GitHub MCP Server via Docker, connects to it over stdio, enumerates every tool it exposes, and runs a full security analysis:

```bash
curl -s -X POST http://127.0.0.1:3002/v1/discover/stdio \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $SAF_MCP_API_KEYS" \
  -d "{
    \"command\": \"docker\",
    \"args\": [\"run\", \"-i\", \"--rm\", \"-e\", \"GITHUB_PERSONAL_ACCESS_TOKEN\", \"ghcr.io/github/github-mcp-server\"],
    \"env\": {
      \"GITHUB_PERSONAL_ACCESS_TOKEN\": \"$GITHUB_PERSONAL_ACCESS_TOKEN\"
    }
  }" | python3 -m json.tool
```

<details>
<summary>Windows alternatives</summary>

**PowerShell:**
```powershell
$pat = $env:GITHUB_PERSONAL_ACCESS_TOKEN
$body = @{
  command = "docker"
  args = @("run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server")
  env = @{ GITHUB_PERSONAL_ACCESS_TOKEN = $pat }
} | ConvertTo-Json -Depth 3
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:3002/v1/discover/stdio -ContentType "application/json" -Headers @{ "X-Api-Key" = $env:SAF_MCP_API_KEYS } -Body $body | ConvertTo-Json -Depth 10
```

**CMD:**
```cmd
curl.exe -s -X POST http://127.0.0.1:3002/v1/discover/stdio -H "Content-Type: application/json" -H "X-Api-Key: %SAF_MCP_API_KEYS%" -d "{\"command\":\"docker\",\"args\":[\"run\",\"-i\",\"--rm\",\"-e\",\"GITHUB_PERSONAL_ACCESS_TOKEN\",\"ghcr.io/github/github-mcp-server\"],\"env\":{\"GITHUB_PERSONAL_ACCESS_TOKEN\":\"%GITHUB_PERSONAL_ACCESS_TOKEN%\"}}"
```

</details>

**What happens behind the scenes:**

1. SAF-MCP spawns `docker run -i --rm ... ghcr.io/github/github-mcp-server` as a child process
2. It speaks MCP protocol over stdio to the container
3. It calls `tools/list` to enumerate every tool the server registers
4. It feeds all discovered tool definitions through the 32-rule security engine
5. You get back the full discovery + analysis in one response

### What to look for in the output

The response has two sections:

**`discovered`** — what the server exposes:

```json
{
  "serverName": "github-mcp-server",
  "serverVersion": "...",
  "toolCount": 30,
  "tools": [ ... ]
}
```

**`analysis`** — SAF-MCP's security assessment:

```json
{
  "summary": {
    "overallRisk": "...",
    "totalFindings": 5,
    "bySeverity": { "Critical": 1, "High": 2, "Medium": 2 }
  },
  "findings": [
    {
      "ruleId": "RULE-006",
      "severity": "Critical",
      "technique": { "id": "SAFE-T1101", "name": "..." },
      "description": "...",
      "evidence": "Tool 'run_command' ...",
      "mitigations": [...],
      "mappings": {
        "stride": ["E", "T"],
        "atlas": [{ "id": "AML.T0053", "name": "AI Agent Tool Invocation" }],
        "owaspLlm": [{ "id": "LLM05", "name": "Improper Output Handling" }],
        "nistAiRmf": [{ "id": "MEASURE-2.6", "function": "MEASURE" }]
      }
    }
  ],
  "frameworkCoverage": [
    { "framework": "STRIDE", "totalMapped": 5 },
    { "framework": "OWASP LLM Top 10 (2025)", "totalMapped": 5 },
    { "framework": "MITRE ATLAS", "totalMapped": 5 },
    { "framework": "NIST AI RMF", "totalMapped": 5 }
  ]
}
```

> Exact findings will vary depending on which toolsets the GitHub MCP Server has enabled. The default toolset already exposes tools for creating files, managing issues, and running actions — all interesting from a security perspective.

### Step 3 — Scan with specific toolsets

The GitHub MCP Server supports [toolsets](https://github.com/github/github-mcp-server#tool-configuration) to control which tools are enabled. Try scanning with everything turned on:

```bash
curl -s -X POST http://127.0.0.1:3002/v1/discover/stdio \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $SAF_MCP_API_KEYS" \
  -d "{
    \"command\": \"docker\",
    \"args\": [\"run\", \"-i\", \"--rm\",
      \"-e\", \"GITHUB_PERSONAL_ACCESS_TOKEN\",
      \"-e\", \"GITHUB_TOOLSETS=all\",
      \"ghcr.io/github/github-mcp-server\"],
    \"env\": {
      \"GITHUB_PERSONAL_ACCESS_TOKEN\": \"$GITHUB_PERSONAL_ACCESS_TOKEN\"
    }
  }" | python3 -m json.tool
```

<details>
<summary>Windows alternatives</summary>

**PowerShell:**
```powershell
$pat = $env:GITHUB_PERSONAL_ACCESS_TOKEN
$body = @{
  command = "docker"
  args = @("run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "-e", "GITHUB_TOOLSETS=all", "ghcr.io/github/github-mcp-server")
  env = @{ GITHUB_PERSONAL_ACCESS_TOKEN = $pat }
} | ConvertTo-Json -Depth 3
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:3002/v1/discover/stdio -ContentType "application/json" -Headers @{ "X-Api-Key" = $env:SAF_MCP_API_KEYS } -Body $body | ConvertTo-Json -Depth 10
```

</details>

Compare the `toolCount` and `totalFindings` against the default run. More tools = more attack surface.

### Step 4 — Dig into a specific finding

Pick a technique ID from the findings (e.g., `SAFE-T1101`) and look it up:

```bash
curl -s http://127.0.0.1:3002/v1/techniques/SAFE-T1101 | python3 -m json.tool
```

This shows the full technique description, severity, MITRE ATT&CK tactic, detection guidance, and linked mitigations.

### Step 5 — Scan a config file instead

If your audience uses Claude Desktop or VS Code, you can scan an entire MCP config at once. This discovers all servers in the config, including the GitHub MCP Server:

```bash
curl -s -X POST http://127.0.0.1:3002/v1/discover/config \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $SAF_MCP_API_KEYS" \
  -d "{
    \"configJson\": \"{\\\"mcpServers\\\":{\\\"github\\\":{\\\"command\\\":\\\"docker\\\",\\\"args\\\":[\\\"run\\\",\\\"-i\\\",\\\"--rm\\\",\\\"-e\\\",\\\"GITHUB_PERSONAL_ACCESS_TOKEN\\\",\\\"ghcr.io/github/github-mcp-server\\\"],\\\"env\\\":{\\\"GITHUB_PERSONAL_ACCESS_TOKEN\\\":\\\"$GITHUB_PERSONAL_ACCESS_TOKEN\\\"}}}}\"
  }" | python3 -m json.tool
```

<details>
<summary>Windows alternatives</summary>

**PowerShell:**
```powershell
$pat = $env:GITHUB_PERSONAL_ACCESS_TOKEN
$config = @{
  mcpServers = @{
    github = @{
      command = "docker"
      args = @("run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server")
      env = @{ GITHUB_PERSONAL_ACCESS_TOKEN = $pat }
    }
  }
} | ConvertTo-Json -Depth 4 -Compress
$body = @{ configJson = $config } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:3002/v1/discover/config -ContentType "application/json" -Headers @{ "X-Api-Key" = $env:SAF_MCP_API_KEYS } -Body $body | ConvertTo-Json -Depth 10
```

</details>

> **Tip for live demos:** Save your actual `claude_desktop_config.json` or VS Code `settings.json` and pass it in. The audience sees their own setup being analyzed — it's a great "oh wow" moment.

## Talking Points

| Moment | What to say |
|---|---|
| Tool count | "The GitHub MCP Server exposes N tools. That's N potential attack vectors an agent can invoke." |
| Findings appear | "We didn't write a single line of config — the skill auto-discovered everything and found real issues." |
| Mitigations | "Every finding comes with specific, actionable mitigations — not just 'be careful'." |
| Toolsets comparison | "Enabling 'all' toolsets doubled the attack surface. This is why least-privilege matters." |
| Config scan | "In CI/CD, you can scan your MCP config file on every commit to catch regressions." |

## Cleanup

Stop the REST server with `Ctrl+C`. The Docker containers are `--rm` so they clean up automatically.
