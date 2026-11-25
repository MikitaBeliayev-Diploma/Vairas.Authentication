using Microsoft.Extensions.Options;

namespace Vairas.Authentication.Configuration.Options;

public sealed class AuthOptionsValidator : IValidateOptions<AuthOptions>
{
    public ValidateOptionsResult Validate(string? name, AuthOptions auth)
    {
        if (!HttpsUrl.IsValid(auth.Issuer) || auth.Issuer.EndsWith('/') || string.IsNullOrWhiteSpace(auth.UserAudience) || string.IsNullOrWhiteSpace(auth.WorkloadAudience) ||
            !auth.UserAudiences.Contains(auth.UserAudience, StringComparer.Ordinal) || auth.UserAudiences.Contains(auth.WorkloadAudience, StringComparer.Ordinal))
            return ValidateOptionsResult.Fail("Configure an HTTPS issuer, distinct workload audience and user audiences.");
        foreach (var pair in auth.ScopeAudiences)
            if (string.IsNullOrWhiteSpace(pair.Key) || pair.Key.Any(char.IsWhiteSpace) || pair.Value.Length == 0 ||
                pair.Value.Any(a => string.IsNullOrWhiteSpace(a) || auth.UserAudiences.Contains(a, StringComparer.Ordinal)))
                return ValidateOptionsResult.Fail("Scope audiences must be explicit internal resources.");
        foreach (var pair in auth.WorkloadClients)
            if (string.IsNullOrWhiteSpace(pair.Key) || pair.Key.Length > 128 || !pair.Value.SecretHash.StartsWith("$argon2id$", StringComparison.Ordinal) ||
                pair.Value.Scopes.Any(s => !auth.ScopeAudiences.ContainsKey(s)))
                return ValidateOptionsResult.Fail("Invalid workload client configuration.");
        foreach (var provider in auth.OidcProviders.Values)
            if (!HttpsUrl.IsValid(provider.Issuer) || provider.Issuer.Length > 512 || string.IsNullOrWhiteSpace(provider.ClientId) || provider.RedirectUris.Length == 0 ||
                provider.RedirectUris.Any(r => !HttpsUrl.IsValid(r) || r.Length > 1024) || provider.SigningAlgorithms.Length == 0 ||
                provider.SigningAlgorithms.Any(a => a is not ("RS256" or "ES256")))
                return ValidateOptionsResult.Fail("Invalid OIDC allowlist configuration.");
        if (auth.OidcProviders.Values.Select(p => p.Issuer).Distinct(StringComparer.Ordinal).Count() != auth.OidcProviders.Count)
            return ValidateOptionsResult.Fail("OIDC issuers must be unique.");
        foreach (var origin in auth.BrowserOrigins)
            if (!HttpsUrl.IsValid(origin) || new Uri(origin).GetLeftPart(UriPartial.Authority) != origin)
                return ValidateOptionsResult.Fail("Browser origins must be exact HTTPS origins.");
        if (auth.OidcCookieSameSite is not ("Lax" or "None") || auth.OidcCookieSameSite == "None" && auth.BrowserOrigins.Length == 0)
            return ValidateOptionsResult.Fail("Cross-site OIDC cookies require explicit browser origins.");
        return ValidateOptionsResult.Success;
    }
}
