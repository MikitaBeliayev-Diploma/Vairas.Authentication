using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.Tokens;
using Moq;
using NUnit.Framework;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration;
using Vairas.Authentication.Security;
using Vairas.Authentication.Configuration.Options;

namespace Vairas.Authentication.Tests;

[TestFixture, Category("Unit")]
public sealed class KeyLifecycleTests
{
    private static (string Pfx, string Cer) Certificate(string directory, string name)
    {
        Directory.CreateDirectory(directory);
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=" + name, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(2));
        var pfx = Path.Combine(directory, name + ".pfx"); var cer = Path.Combine(directory, name + ".cer");
        File.WriteAllBytes(pfx, certificate.Export(X509ContentType.Pfx, "synthetic-test-only"));
        File.WriteAllBytes(cer, certificate.Export(X509ContentType.Cert));
        return (pfx, cer);
    }
    [Test]
    public void EncryptedKeyRingSurvivesProviderRestartAndSeparatesMailFromOidcPurposes()
    {
        var directory = Path.Combine(Path.GetTempPath(), "vairas-key-lifecycle-" + Guid.NewGuid().ToString("N"));
        var certificate = Certificate(directory, "wrapping");
        IDataProtectionProvider Create() => DataProtectionProvider.Create(new DirectoryInfo(Path.Combine(directory, "keys")), o =>
        {
            o.SetApplicationName("Vairas.Authentication");
            o.ProtectKeysWithCertificate(X509CertificateLoader.LoadPkcs12FromFile(certificate.Pfx, "synthetic-test-only", X509KeyStorageFlags.EphemeralKeySet));
        });
        var secret = AuthPolicy.RandomSecret();
        var first = new SecretProtector(Create());
        var protectedValue = first.Protect("mail", secret);
        var restarted = new SecretProtector(Create());
        Assert.That(restarted.Unprotect("mail", protectedValue), Is.EqualTo(secret));
        Business.ThrowsBusiness(() => restarted.Unprotect("oidc", protectedValue));
        Business.ThrowsBusiness(() => restarted.Unprotect("mail", "invalid-ciphertext"));
        var xml = string.Join("\n", Directory.GetFiles(Path.Combine(directory, "keys"), "*.xml").Select(File.ReadAllText));
        Assert.That(xml, Does.Contain("encryptedSecret").And.Not.Contain(secret));
    }
    [Test]
    public void SigningKeyRolloverKeepsOldJwtVerifiableOnlyWhileItsPublicKeyIsRetained()
    {
        var directory = Path.Combine(Path.GetTempPath(), "vairas-signing-lifecycle-" + Guid.NewGuid().ToString("N"));
        var old = Certificate(directory, "old"); var current = Certificate(directory, "current");
        var oldOptions = new AuthOptions { SigningCertificatePath = old.Pfx, SigningCertificatePassword = "synthetic-test-only" };
        using var oldKeys = new SigningKeys(oldOptions);
        var issuer = new TokenService(oldOptions, oldKeys, Mock.Of<IPasswordHasher>(), TimeProvider.System);
        var now = DateTimeOffset.UtcNow;
        var identity = Guid.NewGuid(); var token = issuer.Issue(identity, Guid.NewGuid(), now, now.AddMinutes(15));
        using var rolled = new SigningKeys(new() { SigningCertificatePath = current.Pfx, SigningCertificatePassword = "synthetic-test-only", PreviousCertificates = [old.Cer] });
        TokenValidationParameters Parameters(IEnumerable<SecurityKey> keys) => new()
        {
            ValidIssuer = oldOptions.Issuer, ValidAudience = oldOptions.UserAudience, ValidateIssuer = true, ValidateAudience = true,
            ValidateIssuerSigningKey = true, RequireSignedTokens = true, RequireExpirationTime = true, ValidateLifetime = true,
            IssuerSigningKeys = keys, ValidAlgorithms = ["RS256"]
        };
        var principal = new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(token, Parameters(rolled.ValidationKeys), out _);
        Assert.That(principal.FindFirst("sub")!.Value, Is.EqualTo(identity.ToString("D")));
        using var retired = new SigningKeys(new() { SigningCertificatePath = current.Pfx, SigningCertificatePassword = "synthetic-test-only" });
        Assert.Catch<SecurityTokenException>(() => new JwtSecurityTokenHandler().ValidateToken(token, Parameters(retired.ValidationKeys), out _));
        using var jwks = JsonDocument.Parse(JsonSerializer.Serialize(rolled.PublicJwks()));
        Assert.That(jwks.RootElement.GetProperty("keys").GetArrayLength(), Is.EqualTo(2));
        Assert.That(jwks.RootElement.GetProperty("keys").EnumerateArray().Any(k => k.TryGetProperty("d", out _)), Is.False);
    }
}
