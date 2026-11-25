using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration;
using Vairas.Authentication.Configuration.Options;

namespace Vairas.Authentication.Security;


public sealed class SigningKeys : IDisposable
{
    private readonly List<X509Certificate2> certificates = [];
    private readonly TimeProvider clock;
    private readonly DateTimeOffset notBefore;
    private readonly DateTimeOffset notAfter;
    public SigningCredentials Credentials { get; }
    public IReadOnlyList<SecurityKey> ValidationKeys { get; }
    public SigningKeys(AuthOptions options, TimeProvider? clock = null)
    {
        this.clock = clock ?? TimeProvider.System;
        if (string.IsNullOrEmpty(options.SigningCertificatePath)) throw new InvalidOperationException("Authentication signing certificate is required.");
        var certificate = X509CertificateLoader.LoadPkcs12FromFile(options.SigningCertificatePath, options.SigningCertificatePassword, X509KeyStorageFlags.EphemeralKeySet);
        certificates.Add(certificate);
        notBefore = certificate.NotBefore.ToUniversalTime();
        notAfter = certificate.NotAfter.ToUniversalTime();
        if (!certificate.HasPrivateKey || !CanIssueTokens)
        {
            Dispose();
            throw new InvalidOperationException("A private signing key valid for the entire access-token lifetime is required.");
        }
        var active = Key(certificate);
        Credentials = new SigningCredentials(active, SecurityAlgorithms.RsaSha256);
        var keys = new List<SecurityKey> { active };
        foreach (var path in options.PreviousCertificates)
        {
            var previous = X509CertificateLoader.LoadCertificateFromFile(path);
            certificates.Add(previous);
            keys.Add(Key(previous));
        }
        if (keys.Select(x => x.KeyId).Distinct().Count() != keys.Count) throw new InvalidOperationException("Duplicate signing key IDs.");
        ValidationKeys = keys;
    }
    // Readiness and issuance use the same active-certificate window. Retained public
    // certificates remain available to verify tokens issued before key rotation.
    public bool CanIssueTokens
    {
        get
        {
            var now = clock.GetUtcNow();
            return CoversLifetime(now, now, now.AddSeconds(TokenService.AccessTokenLifetimeSeconds));
        }
    }
    public bool CanSign(DateTimeOffset issuedAt, DateTimeOffset expiresAt) =>
        CoversLifetime(clock.GetUtcNow(), issuedAt, expiresAt);
    private bool CoversLifetime(DateTimeOffset now, DateTimeOffset issuedAt, DateTimeOffset expiresAt) =>
        now >= notBefore && now < notAfter && issuedAt >= notBefore &&
        expiresAt > issuedAt && expiresAt <= notAfter;
    private static X509SecurityKey Key(X509Certificate2 certificate)
    {
        using var rsa = certificate.GetRSAPublicKey();
        if (rsa is null || rsa.KeySize < 2048) throw new InvalidOperationException("RSA keys of at least 2048 bits are required.");
        return new(certificate) { KeyId = Convert.ToHexStringLower(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo())) };
    }
    public object PublicJwks() => new { keys = certificates.Select(c =>
    {
        using var rsa = c.GetRSAPublicKey();
        var p = rsa!.ExportParameters(false);
        return new { kty = "RSA", use = "sig", alg = "RS256", kid = Key(c).KeyId,
            n = Base64UrlEncoder.Encode(p.Modulus!), e = Base64UrlEncoder.Encode(p.Exponent!) };
    }).ToArray() };
    public void Dispose() { foreach (var certificate in certificates) certificate.Dispose(); }
}
