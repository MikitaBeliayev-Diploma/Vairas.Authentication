namespace Vairas.Authentication.Configuration.Options;


public sealed class OidcProviderOptions
{
    public string Issuer { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string? ClientSecret { get; set; }
    public string[] RedirectUris { get; set; } = [];
    public string[] EndpointHosts { get; set; } = [];
    public string[] SigningAlgorithms { get; set; } = ["RS256"];
}
