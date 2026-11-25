using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

public static class AuthPolicy
{
    public static DateTimeOffset Now(TimeProvider clock) { var n = clock.GetUtcNow(); return n.AddTicks(-(n.Ticks % 10)); }
    public static string Email(string? email)
    {
        if (string.IsNullOrWhiteSpace(email) || email.Length > 254) throw AuthErrors.Invalid();
        var value = email.Trim().ToLowerInvariant();
        if (value.Any(c => c < 33 || c > 126) || !MailAddress.TryCreate(value, out var address) || address.Address != value)
            throw AuthErrors.Invalid();
        return value;
    }
    public static void Password(string? value, bool creating)
    {
        if (value is null || value.Length > 128 || value.Length < (creating ? 12 : 1)) throw AuthErrors.Invalid();
    }
    public static void Secret(string? value)
    {
        if (value is null || value.Length != 43 || value.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')))
            throw AuthErrors.Invalid();
    }
    public static string RandomSecret() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public static string Digest(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    public static bool EqualDigest(string a, string b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
    public static bool Active(Identity? identity, AuthSession? session, DateTimeOffset now) => identity is { SecurityState: "Enabled" } &&
        session is not null && session.IdentityId == identity.IdentityId && session.RevokedAt is null && session.ExpiresAt > now;
    public static string RevocationFingerprint(Guid identity, Guid target) => Digest($"v1:RevokeSession:{identity:D}:{target:D}");
    public static string CookieName(string state) => "__Host-vairas-oidc-" + Digest(state)[..24];
}
