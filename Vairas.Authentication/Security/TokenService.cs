using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration;
using Vairas.Authentication.Configuration.Options;

namespace Vairas.Authentication.Security;


public sealed class TokenService(AuthOptions options, SigningKeys keys, IPasswordHasher passwords, TimeProvider clock) : IUserTokenIssuer, IWorkloadTokenService
{
    public const int AccessTokenLifetimeSeconds = 900;
    public int LifetimeSeconds => AccessTokenLifetimeSeconds;
    public string Issue(Guid identity, Guid session, DateTimeOffset now, DateTimeOffset expiresAt) =>
        Sign(identity.ToString("D"), options.UserAudiences, [new("sid", session.ToString("D"))], now, expiresAt);
    public WorkloadTokenResponse Issue(string grant, string client, string secret, string scope)
    {
        if (grant != "client_credentials" || string.IsNullOrWhiteSpace(client) || client.Length > 128 || string.IsNullOrWhiteSpace(secret) || secret.Length > 256 || scope.Length > 4096)
            throw AuthErrors.Invalid();
        if (!options.WorkloadClients.TryGetValue(client, out var allowed)) { passwords.DummyVerify(secret); throw AuthErrors.Denied(); }
        if (!passwords.Verify(allowed.SecretHash, secret)) throw AuthErrors.Denied();
        var scopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        if (scopes.Length == 0 || scopes.Any(s => !allowed.Scopes.Contains(s, StringComparer.Ordinal) || !options.ScopeAudiences.ContainsKey(s)))
            throw new BadRequestException("INVALID_SCOPE", "The requested scopes are not permitted.");
        var now = AuthPolicy.Now(clock);
        var value = Sign(client, scopes.SelectMany(s => options.ScopeAudiences[s]).Distinct(StringComparer.Ordinal), [new("scope", string.Join(' ', scopes))], now, now.AddSeconds(LifetimeSeconds));
        return new(value, "Bearer", LifetimeSeconds, string.Join(' ', scopes));
    }
    public bool Allowed(ClaimsPrincipal caller, string requiredScope)
    {
        var client = caller.FindFirstValue("sub");
        return client is not null && options.WorkloadClients.TryGetValue(client, out var c) && c.Scopes.Contains(requiredScope, StringComparer.Ordinal) &&
            caller.FindAll("scope").SelectMany(x => x.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries)).Contains(requiredScope, StringComparer.Ordinal);
    }
    internal string Sign(string subject, IEnumerable<string> audiences, IEnumerable<Claim> claims, DateTimeOffset now, DateTimeOffset expires)
    {
        if (!keys.CanSign(now, expires)) throw AuthErrors.Dependency();
        var values = claims.Concat([new Claim("sub", subject), new Claim("jti", Guid.NewGuid().ToString("D")),
            new Claim("iat", now.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), ClaimValueTypes.Integer64)])
            .Concat(audiences.Select(a => new Claim("aud", a)));
        var jwt = new JwtSecurityToken(options.Issuer, claims: values, notBefore: now.UtcDateTime, expires: expires.UtcDateTime, signingCredentials: keys.Credentials);
        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }
}
