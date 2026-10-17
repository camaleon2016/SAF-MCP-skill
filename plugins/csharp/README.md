# SAF-MCP Semantic Kernel Plugin

A C# plugin that exposes all SAF-MCP security analysis capabilities as
Semantic Kernel functions. Agents using SK can call these directly via
automatic function calling.

## Prerequisites

- .NET 8.0+
- The SAF-MCP REST API running locally (`npm run start:rest` from the root project)

## Installation

```bash
cd plugins/csharp/SafeMcpSkill
dotnet build
```

## Usage

### Register the plugin

```csharp
using Microsoft.SemanticKernel;
using SafeMcpSkill;

var builder = Kernel.CreateBuilder();
builder.AddOpenAIChatCompletion("gpt-4o", Environment.GetEnvironmentVariable("OPENAI_API_KEY")!);
var kernel = builder.Build();

// Add the SAF-MCP plugin
kernel.AddSafeMcpPlugin(baseUrl: "http://127.0.0.1:3002");
```

### Available kernel functions

| Function | Description |
| --- | --- |
| `analyze_architecture` | Full security analysis on an agent architecture |
| `analyze_tool` | Analyze a single MCP tool definition |
| `analyze_server` | Analyze an MCP server definition |
| `get_technique` | Look up a SAF-MCP technique by ID |
| `get_mitigation` | Look up a SAF-MCP mitigation by ID |
| `search_techniques` | Search techniques by keyword |
| `search_mitigations` | Search mitigations by keyword |
| `get_threat_profile` | Get the overall threat landscape |
| `get_framework_stats` | Get framework statistics |

### Example: Automatic function calling

```csharp
var settings = new OpenAIPromptExecutionSettings
{
    FunctionChoiceBehavior = FunctionChoiceBehavior.Auto()
};

var result = await kernel.InvokePromptAsync(
    "Analyze this tool for security risks: name='execute_code', description='Runs arbitrary Python code on the server'",
    new(settings));

Console.WriteLine(result);
```

The LLM will automatically invoke `analyze_tool` and summarize the findings.

## Architecture

```
SafeMcpClient  ──HTTP──▶  SAF-MCP REST API (:3002)
      ▲                        │
      │                        ▼
SafeMcpPlugin            Engine (rules.ts + analyze.ts)
      ▲
      │
Semantic Kernel (auto function calling)
```
