using System.Net.Http.Json;
using System.Text.Json;
using SafeMcpSkill.Models;

namespace SafeMcpSkill;

/// <summary>
/// HTTP client for the SAF-MCP REST API.
/// Used internally by the Semantic Kernel plugin.
/// </summary>
public sealed class SafeMcpClient : IDisposable
{
    private readonly HttpClient _http;
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
    };

    public SafeMcpClient(string baseUrl = "http://127.0.0.1:3002", string? apiKey = null)
    {
        _http = new HttpClient { BaseAddress = new Uri(baseUrl) };
        if (!string.IsNullOrEmpty(apiKey))
            _http.DefaultRequestHeaders.Add("X-Api-Key", apiKey);
    }

    public SafeMcpClient(HttpClient httpClient)
    {
        _http = httpClient;
    }

    public async Task<AnalysisResult> AnalyzeArchitectureAsync(AgentArchitecture architecture, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/v1/analyze/architecture", architecture, JsonOpts, ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<AnalysisResult>(JsonOpts, ct)
            ?? throw new InvalidOperationException("Empty response");
    }

    public async Task<AnalysisResult> AnalyzeToolAsync(ToolDefinition tool, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/v1/analyze/tool", tool, JsonOpts, ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<AnalysisResult>(JsonOpts, ct)
            ?? throw new InvalidOperationException("Empty response");
    }

    public async Task<AnalysisResult> AnalyzeServerAsync(ServerDefinition server, CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/v1/analyze/server", server, JsonOpts, ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<AnalysisResult>(JsonOpts, ct)
            ?? throw new InvalidOperationException("Empty response");
    }

    public async Task<string> GetTechniqueAsync(string id, CancellationToken ct = default)
    {
        var response = await _http.GetAsync($"/v1/techniques/{Uri.EscapeDataString(id)}", ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync(ct);
    }

    public async Task<string> GetMitigationAsync(string id, CancellationToken ct = default)
    {
        var response = await _http.GetAsync($"/v1/mitigations/{Uri.EscapeDataString(id)}", ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync(ct);
    }

    public async Task<string> SearchTechniquesAsync(string query, CancellationToken ct = default)
    {
        var response = await _http.GetAsync($"/v1/techniques?q={Uri.EscapeDataString(query)}", ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync(ct);
    }

    public async Task<string> SearchMitigationsAsync(string query, CancellationToken ct = default)
    {
        var response = await _http.GetAsync($"/v1/mitigations?q={Uri.EscapeDataString(query)}", ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync(ct);
    }

    public async Task<string> GetThreatProfileAsync(CancellationToken ct = default)
    {
        var response = await _http.GetAsync("/v1/threat-profile", ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync(ct);
    }

    public async Task<string> GetFrameworkStatsAsync(CancellationToken ct = default)
    {
        var response = await _http.GetAsync("/v1/framework/stats", ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync(ct);
    }

    public void Dispose() => _http.Dispose();
}
