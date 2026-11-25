namespace Vairas.Authentication.Configuration.Options;


public sealed class WorkloadClientOptions
{
    public bool AllowTokenExchange { get; set; }
    public string SecretHash { get; set; } = "";
    public string[] Scopes { get; set; } = [];
}
