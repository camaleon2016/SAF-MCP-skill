using System.ComponentModel;
using System.Text.Json;
using Microsoft.SemanticKernel;
using SafeMcpSkill.Models;

namespace SafeMcpSkill;

/// <summary>
/// Semantic Kernel plugin that exposes SAF-MCP security analysis capabilities.
/// Register with: kernel.ImportPluginFromObject(new SafeMcpPlugin(client));
/// </summary>
public sealed class SafeMcpPlugin
{
    private readonly SafeMcpClient _client;
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public SafeMcpPlugin(SafeMcpClient client) => _client = client;

    [KernelFunction("analyze_architecture")]
    [Description("Run a full SAF-MCP security analysis on an agent architecture. Provide a JSON object with fields: name, servers, tools, multiAgent, sharedMemory, vectorStore, ragPipeline, multimodal, cliAccess, fileSystemAccess, networkAccess, oauthFlows.")]
    public async Task<string> AnalyzeArchitectureAsync(
        [Description("JSON string of the AgentArchitecture object")] string architectureJson,
        CancellationToken ct = default)
    {
        var arch = JsonSerializer.Deserialize<AgentArchitecture>(architectureJson)
            ?? throw new ArgumentException("Invalid architecture JSON");
        var result = await _client.AnalyzeArchitectureAsync(arch, ct);
        return JsonSerializer.Serialize(result, JsonOpts);
    }

    [KernelFunction("analyze_tool")]
    [Description("Analyze a single MCP tool definition for security risks. Provide tool name and description.")]
    public async Task<string> AnalyzeToolAsync(
        [Description("Tool name")] string name,
        [Description("Tool description text")] string description,
        CancellationToken ct = default)
    {
        var result = await _client.AnalyzeToolAsync(new ToolDefinition(name, description), ct);
        return JsonSerializer.Serialize(result, JsonOpts);
    }

    [KernelFunction("analyze_server")]
    [Description("Analyze an MCP server definition for security risks. Provide a JSON string of the server definition.")]
    public async Task<string> AnalyzeServerAsync(
        [Description("JSON string of the ServerDefinition object")] string serverJson,
        CancellationToken ct = default)
    {
        var server = JsonSerializer.Deserialize<ServerDefinition>(serverJson)
            ?? throw new ArgumentException("Invalid server JSON");
        var result = await _client.AnalyzeServerAsync(server, ct);
        return JsonSerializer.Serialize(result, JsonOpts);
    }

    [KernelFunction("get_technique")]
    [Description("Get full details for a SAF-MCP technique by ID (e.g., SAFE-T1001).")]
    public async Task<string> GetTechniqueAsync(
        [Description("Technique ID such as SAFE-T1001")] string id,
        CancellationToken ct = default)
    {
        return await _client.GetTechniqueAsync(id, ct);
    }

    [KernelFunction("get_mitigation")]
    [Description("Get full details for a SAF-MCP mitigation by ID (e.g., SAFE-M-1).")]
    public async Task<string> GetMitigationAsync(
        [Description("Mitigation ID such as SAFE-M-1")] string id,
        CancellationToken ct = default)
    {
        return await _client.GetMitigationAsync(id, ct);
    }

    [KernelFunction("search_techniques")]
    [Description("Search SAF-MCP techniques by keyword.")]
    public async Task<string> SearchTechniquesAsync(
        [Description("Search keyword")] string query,
        CancellationToken ct = default)
    {
        return await _client.SearchTechniquesAsync(query, ct);
    }

    [KernelFunction("search_mitigations")]
    [Description("Search SAF-MCP mitigations by keyword.")]
    public async Task<string> SearchMitigationsAsync(
        [Description("Search keyword")] string query,
        CancellationToken ct = default)
    {
        return await _client.SearchMitigationsAsync(query, ct);
    }

    [KernelFunction("get_threat_profile")]
    [Description("Get the overall SAF-MCP threat profile with severity distribution, unmitigated techniques, and coverage score.")]
    public async Task<string> GetThreatProfileAsync(CancellationToken ct = default)
    {
        return await _client.GetThreatProfileAsync(ct);
    }

    [KernelFunction("get_framework_stats")]
    [Description("Get SAF-MCP framework statistics including totals, tactic distribution, and implementation guidance.")]
    public async Task<string> GetFrameworkStatsAsync(CancellationToken ct = default)
    {
        return await _client.GetFrameworkStatsAsync(ct);
    }
}
