using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration;
using Vairas.Delegation;
using Vairas.Authentication.Configuration.Options;

namespace Vairas.Authentication.Security;


public sealed class TokenExchange(AuthOptions options, SigningKeys keys, IPasswordHasher passwords, TokenService signer, IAuthenticationService authentication, TimeProvider clock)
{
    public async Task<ExchangeTokenResponse> IssueAsync(string client, string secret, string subject, string subjectType, string? requestedType, string resource, string scope, string schoolId, CancellationToken ct, string? lessonAction = null)
    {
        static BadRequestException Invalid(string code = "INVALID_GRANT") => new(code, "The requested token exchange is not permitted.");
        if (!options.Delegation.Enabled) throw Invalid("UNSUPPORTED_GRANT_TYPE");
        if (client.Length is < 1 or > 128 || secret.Length is < 1 or > 256 || subject.Length is < 1 or > 16384 || resource.Length > 2048 || scope.Length > 4096 || subjectType != ReadPreviewDelegation.AccessTokenType || requestedType is not (null or "") && requestedType != ReadPreviewDelegation.AccessTokenType || !Guid.TryParse(schoolId, out var school) || school == Guid.Empty) throw Invalid();
        if (!options.WorkloadClients.TryGetValue(client, out var credentials)) { passwords.DummyVerify(secret); throw AuthErrors.Denied(); }
        if (!passwords.Verify(credentials.SecretHash, secret) || !credentials.AllowTokenExchange) throw AuthErrors.Denied();
        if (client is not ("chat-backend" or "mcp-server")) throw Invalid();
        var scopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        var execution = scopes.Length == 1 && new[] { "mcp.create_lesson_booking", "mcp.reschedule_lesson_booking" }.Contains(scopes[0], StringComparer.Ordinal);
        if (execution ? !options.Delegation.ConfirmedLessonActionsEnabled : lessonAction is not null || scopes.Length == 0 || scopes.Except(ReadPreviewDelegation.Scopes, StringComparer.Ordinal).Any()) throw Invalid("INVALID_SCOPE");
        var policy = options.Delegation;
        static bool Https(string uri) => Uri.TryCreate(uri, UriKind.Absolute, out var parsed) && parsed.Scheme == "https" && parsed.UserInfo.Length == 0 && parsed.Query.Length == 0 && parsed.Fragment.Length == 0;
        if (!Https(policy.McpResource) || policy.Resources.Count != 4 || policy.Resources.Any(p => !Https(p.Value) || ReadPreviewDelegation.ResourceScopes(p.Key).Length == 0) || policy.Resources.Values.Append(policy.McpResource).Distinct(StringComparer.Ordinal).Count() != 5) throw AuthErrors.Dependency();
        var owner = policy.Resources.SingleOrDefault(p => p.Value == resource).Key;
        if (client == "chat-backend" ? resource != policy.McpResource : owner is null) throw Invalid("INVALID_TARGET");
        ClaimsPrincipal principal; JwtSecurityToken source;
        try
        {
            var handler = new JwtSecurityTokenHandler { MapInboundClaims = false, MaximumTokenSizeInBytes = 16384 };
            principal = handler.ValidateToken(subject, new TokenValidationParameters
            {
                ValidateIssuer = true, ValidIssuer = options.Issuer, ValidateAudience = true, ValidAudience = client == "chat-backend" ? "vairas-chat" : policy.McpResource,
                ValidateIssuerSigningKey = true, IssuerSigningKeys = keys.ValidationKeys, RequireSignedTokens = true, ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
                RequireExpirationTime = true, ValidateLifetime = true, ClockSkew = TimeSpan.Zero
            }, out var validated);
            source = (JwtSecurityToken)validated;
        }
        catch (Exception e) when (e is SecurityTokenException or ArgumentException) { throw Invalid(); }
        string One(string name) => principal.FindAll(name).ToArray() is { Length: 1 } values ? values[0].Value : throw Invalid();
        if (!Guid.TryParse(One("sub"), out var identity) || identity == Guid.Empty || !Guid.TryParse(One("sid"), out var session) || session == Guid.Empty) throw Invalid();
        object actor;
        Vairas.ConfirmedActions.LessonActionBinding? binding = null;
        if (client == "chat-backend")
        {
            if (ReadPreviewDelegation.Marked(principal)) throw Invalid();
            actor = new { sub = "chat-backend" };
            if (execution)
            {
                try { binding = JsonSerializer.Deserialize<Vairas.ConfirmedActions.LessonActionBinding>(lessonAction ?? "", Vairas.ConfirmedActions.LessonActions.Json); }
                catch (JsonException) { throw Invalid(); }
                if (binding is null || binding.Kind is not ("Booking" or "Rescheduling") || binding.IdentityId != identity || binding.SessionId != session || binding.SchoolId != school || Vairas.ConfirmedActions.LessonActions.Scope(binding.Kind) != scope || new[] { binding.ConversationId, binding.PreviewId, binding.OperationId, binding.UserId }.Contains(Guid.Empty) || new[] { binding.ActionDigest, binding.CommandDigest }.Any(d => d is null || d.Length != 64 || d.Any(c => !char.IsAsciiHexDigitLower(c)))) throw Invalid();
            }
        }
        else
        {
            if (execution)
            {
                try { binding = Vairas.ConfirmedActions.LessonActions.Parse(principal, 1); }
                catch (Exception e) when (e is InvalidOperationException or JsonException or FormatException or KeyNotFoundException) { throw Invalid(); }
                if (owner != "scheduling" || source.Audiences.Count() != 1 || binding.SchoolId != school || Vairas.ConfirmedActions.LessonActions.Scope(binding.Kind) != scope || lessonAction is not null) throw Invalid("INVALID_SCOPE");
            }
            else
            {
                DelegatedContext parent;
                try { parent = ReadPreviewDelegation.Parse(principal, 1); } catch (Exception e) when (e is InvalidOperationException or JsonException or FormatException or KeyNotFoundException) { throw Invalid(); }
                if (source.Audiences.Count() != 1 || parent.School != school || scopes.Except(parent.Scopes, StringComparer.Ordinal).Any() || scopes.Except(ReadPreviewDelegation.ResourceScopes(owner!), StringComparer.Ordinal).Any()) throw Invalid("INVALID_SCOPE");
            }
            actor = new { sub = "mcp-server", act = new { sub = "chat-backend" } };
        }
        var active = await authentication.ValidateAsync(new(identity, session), ct);
        if (!active.Active || active.IdentityId != identity || active.SessionId != session) throw Invalid();
        var now = clock.GetUtcNow();
        var expiry = new[] { now.AddSeconds(60), new DateTimeOffset(source.ValidTo, TimeSpan.Zero), active.ValidUntil }.Min();
        var seconds = (int)Math.Floor((expiry - now).TotalSeconds); if (seconds < 1) throw Invalid();
        expiry = DateTimeOffset.FromUnixTimeSeconds(now.ToUnixTimeSeconds() + seconds);
        var claims = new List<Claim> { new("sid", session.ToString("D")), new("school_id", school.ToString("D")), new("vairas_delegation", execution ? Vairas.ConfirmedActions.LessonActions.Profile : ReadPreviewDelegation.Profile), new("scope", string.Join(' ', scopes)), new("act", JsonSerializer.Serialize(actor), JsonClaimValueTypes.Json) };
        if (binding is not null) claims.Add(new(Vairas.ConfirmedActions.LessonActions.Claim, JsonSerializer.Serialize(binding, Vairas.ConfirmedActions.LessonActions.Json), JsonClaimValueTypes.Json));
        var value = signer.Sign(identity.ToString("D"), [client == "chat-backend" ? resource : "vairas-" + owner],
            claims, now, expiry);
        return new(value, ReadPreviewDelegation.AccessTokenType, "Bearer", seconds, string.Join(' ', scopes));
    }
}
