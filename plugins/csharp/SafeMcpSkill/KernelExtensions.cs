using Microsoft.SemanticKernel;
using SafeMcpSkill;

namespace SafeMcpSkill;

/// <summary>
/// Extension methods for registering the SAF-MCP plugin with a Semantic Kernel instance.
/// </summary>
public static class KernelExtensions
{
    /// <summary>
    /// Adds the SAF-MCP Security Analysis plugin to the kernel.
    /// Requires the SAF-MCP REST API to be running (npm run start:rest).
    /// </summary>
    /// <param name="kernel">The Semantic Kernel instance.</param>
    /// <param name="baseUrl">Base URL of the SAF-MCP REST API.</param>
    /// <param name="apiKey">Optional API key for authentication.</param>
    /// <returns>The kernel for chaining.</returns>
    public static Kernel AddSafeMcpPlugin(this Kernel kernel, string baseUrl = "http://127.0.0.1:3002", string? apiKey = null)
    {
        var client = new SafeMcpClient(baseUrl, apiKey);
        var plugin = new SafeMcpPlugin(client);
        kernel.ImportPluginFromObject(plugin, "SafeMcp");
        return kernel;
    }
}
