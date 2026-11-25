using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration;
using Vairas.Authentication.Configuration.Options;

namespace Vairas.Authentication.Integrations;

public sealed class OidcProvider(AuthOptions settings, IHttpClientFactory clients, IHostEnvironment environment) : IOidcProvider
{
    private readonly ConcurrentDictionary<string, ConfigurationManager<OpenIdConnectConfiguration>> managers = new(StringComparer.Ordinal);
    public void Validate(string issuer, string redirectUri)
    {
        var provider = Find(issuer);
        if (!provider.RedirectUris.Contains(redirectUri, StringComparer.Ordinal)) throw AuthErrors.Invalid();
    }
    private OidcProviderOptions Find(string issuer) => settings.OidcProviders.Values.SingleOrDefault(x => x.Issuer == issuer)
        ?? throw new BadRequestException("OIDC_PROVIDER_NOT_ALLOWED", "The external issuer is not configured.");
    private async Task<OpenIdConnectConfiguration> ConfigurationAsync(OidcProviderOptions provider, CancellationToken ct)
    {
        try
        {
            var manager = managers.GetOrAdd(provider.Issuer, issuer => new(issuer.TrimEnd('/') + "/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever(), new SafeDocumentRetriever(clients.CreateClient("oidc"), provider, environment)));
            var config = await manager.GetConfigurationAsync(ct);
            if (config.Issuer != provider.Issuer) throw AuthErrors.Dependency();
            CheckAddress(config.AuthorizationEndpoint, provider, environment);
            CheckAddress(config.TokenEndpoint, provider, environment);
            return config;
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or JsonException || ex is OperationCanceledException && !ct.IsCancellationRequested)
        { throw AuthErrors.Dependency(); }
    }
    public async Task<string> AuthorizationUrlAsync(string issuer, string redirect, string state, string nonce, string verifier, CancellationToken ct)
    {
        Validate(issuer, redirect);
        var provider = Find(issuer);
        var config = await ConfigurationAsync(provider, ct);
        return QueryHelpers.AddQueryString(config.AuthorizationEndpoint, new Dictionary<string, string?>
        {
            ["client_id"] = provider.ClientId, ["response_type"] = "code", ["scope"] = "openid",
            ["redirect_uri"] = redirect, ["state"] = state, ["nonce"] = nonce,
            ["code_challenge_method"] = "S256", ["code_challenge"] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)))
        });
    }
    public async Task<ExternalSubject> ExchangeAsync(string issuer, string redirect, string code, OidcSecrets secrets, CancellationToken ct)
    {
        Validate(issuer, redirect);
        var provider = Find(issuer);
        var config = await ConfigurationAsync(provider, ct);
        try
        {
            var form = new Dictionary<string, string> { ["grant_type"] = "authorization_code", ["code"] = code,
                ["redirect_uri"] = redirect, ["client_id"] = provider.ClientId, ["code_verifier"] = secrets.Verifier };
            if (!string.IsNullOrEmpty(provider.ClientSecret)) form["client_secret"] = provider.ClientSecret;
            using var response = await clients.CreateClient("oidc").PostAsync(config.TokenEndpoint, new FormUrlEncodedContent(form), ct);
            if ((int)response.StatusCode is 400 or 401) throw AuthErrors.Denied();
            if (!response.IsSuccessStatusCode) throw AuthErrors.Dependency();
            await response.Content.LoadIntoBufferAsync(262144, ct);
            var json = await response.Content.ReadAsStringAsync(ct);
            var message = new OpenIdConnectMessage(json);
            if (string.IsNullOrEmpty(message.IdToken)) throw AuthErrors.Denied();
            var handler = new JwtSecurityTokenHandler { MapInboundClaims = false, MaximumTokenSizeInBytes = 65536 };
            ClaimsPrincipalAndToken ValidateToken()
            {
                var principal = handler.ValidateToken(message.IdToken, new TokenValidationParameters
                {
                    ValidateIssuer = true, ValidIssuer = issuer, ValidateAudience = true, ValidAudience = provider.ClientId,
                    ValidateLifetime = true, RequireExpirationTime = true, RequireSignedTokens = true, ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = config.SigningKeys, ValidAlgorithms = provider.SigningAlgorithms, ClockSkew = TimeSpan.FromSeconds(30)
                }, out var validated);
                return new(principal, (JwtSecurityToken)validated);
            }
            ClaimsPrincipalAndToken result;
            try { result = ValidateToken(); }
            catch (SecurityTokenSignatureKeyNotFoundException)
            {
                managers[issuer].RequestRefresh();
                config = await ConfigurationAsync(provider, ct);
                result = ValidateToken();
            }
            // Freshness is enforced by the persisted ten-minute, single-use request, not a middleware-specific nonce prefix.
            new OpenIdConnectProtocolValidator { RequireNonce = true, RequireTimeStampInNonce = false }.ValidateTokenResponse(new()
            {
                ProtocolMessage = message, ValidatedIdToken = result.Token, ClientId = provider.ClientId, Nonce = secrets.Nonce
            });
            var subject = result.Principal.FindFirst("sub")?.Value;
            if (string.IsNullOrWhiteSpace(subject) || subject.Length > 255) throw AuthErrors.Denied();
            return new(issuer, subject);
        }
        catch (Exception ex) when (ex is SecurityTokenException or OpenIdConnectProtocolException or ArgumentException or JsonException)
        { throw AuthErrors.Denied(); }
        catch (Exception ex) when (ex is HttpRequestException || ex is OperationCanceledException && !ct.IsCancellationRequested)
        { throw AuthErrors.Dependency(); }
    }
    private sealed record ClaimsPrincipalAndToken(System.Security.Claims.ClaimsPrincipal Principal, JwtSecurityToken Token);
    private static void CheckAddress(string? address, OidcProviderOptions provider, IHostEnvironment environment)
    {
        if (!Uri.TryCreate(address, UriKind.Absolute, out var uri) || !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment) ||
            (uri.Scheme != "https" && !(environment.IsEnvironment("Testing") && uri.IsLoopback && uri.Scheme == "http"))) throw AuthErrors.Dependency();
        var hosts = provider.EndpointHosts.Length == 0 ? [new Uri(provider.Issuer).Host] : provider.EndpointHosts;
        if (!hosts.Contains(uri.Host, StringComparer.OrdinalIgnoreCase)) throw AuthErrors.Dependency();
    }
    private sealed class SafeDocumentRetriever(HttpClient client, OidcProviderOptions provider, IHostEnvironment environment) : IDocumentRetriever
    {
        public async Task<string> GetDocumentAsync(string address, CancellationToken cancel)
        {
            CheckAddress(address, provider, environment);
            using var response = await client.GetAsync(address, HttpCompletionOption.ResponseHeadersRead, cancel);
            response.EnsureSuccessStatusCode();
            await response.Content.LoadIntoBufferAsync(262144, cancel);
            return await response.Content.ReadAsStringAsync(cancel);
        }
    }
}
