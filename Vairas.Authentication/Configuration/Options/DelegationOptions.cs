namespace Vairas.Authentication.Configuration.Options;


public sealed class DelegationOptions
{
    public bool ConfirmedLessonActionsEnabled { get; set; }
    public bool Enabled { get; set; }
    public string McpResource { get; set; } = "https://localhost:7900/mcp";
    public Dictionary<string, string> Resources { get; set; } = new(StringComparer.Ordinal)
    {
        ["user-management"] = "https://localhost:7001/", ["school-management"] = "https://localhost:7200/",
        ["scheduling"] = "https://localhost:7300/", ["learning-tracking"] = "https://localhost:7500/"
    };
}
