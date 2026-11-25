using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Moq;
using NUnit.Framework;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration;
using Vairas.Authentication.Security;
using Vairas.Authentication.Configuration.Options;

namespace Vairas.Authentication.Tests;

[TestFixture, Category("Unit")]
public sealed class KeyValidityTests
{
    private static readonly DateTimeOffset Start = new(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private string directory = null!;
    private AuthOptions options = null!;

    [SetUp]
    public void CreateSyntheticCertificate()
    {
        directory = Path.Combine(Path.GetTempPath(), "vairas-key-validity-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Vairas-Key-Validity-Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(Start, Start.AddDays(1));
        var path = Path.Combine(directory, "signing.pfx");
        File.WriteAllBytes(path, certificate.Export(X509ContentType.Pfx, "synthetic-only"));
        options = new() { SigningCertificatePath = path, SigningCertificatePassword = "synthetic-only" };
    }

    [TearDown]
    public void RemoveSyntheticCertificate() => Directory.Delete(directory, recursive: true);

    [TestCase(-1)]
    [TestCase(24 * 60)]
    [TestCase(24 * 60 - 14)]
    public void StartupRejectsCertificateOutsideItsFullIssuanceWindow(int minutes)
    {
        var clock = new SigningTestClock(Start.AddMinutes(minutes));
        Assert.Throws<InvalidOperationException>(() => new SigningKeys(options, clock));
    }

    [TestCase(-1, 60, 75)] // Clock moved before NotBefore after loading.
    [TestCase(24 * 60, 60, 75)] // Clock reached NotAfter, even with backdated claims.
    [TestCase(60, -1, 75)] // The token starts before the certificate.
    [TestCase(60, 24 * 60 - 5, 24 * 60 + 10)] // The token outlives the certificate.
    [TestCase(60, 60, 60)] // An empty token lifetime is invalid.
    public void UserIssuanceChecksCurrentTimeAndEntireTokenInterval(int currentMinutes, int issueMinutes, int expiryMinutes)
    {
        var clock = new SigningTestClock(Start.AddHours(1));
        using var keys = new SigningKeys(options, clock);
        var issuer = new TokenService(options, keys, Mock.Of<IPasswordHasher>(), clock);
        clock.Current = Start.AddMinutes(currentMinutes);

        var error = Business.ThrowsBusiness(() => issuer.Issue(Guid.NewGuid(), Guid.NewGuid(),
            Start.AddMinutes(issueMinutes), Start.AddMinutes(expiryMinutes)));

        Assert.That(error.HttpStatus(), Is.EqualTo(503));
        Assert.That(error.Code, Is.EqualTo("DEPENDENCY_UNAVAILABLE"));
    }

    [Test]
    public void WorkloadIssuanceStopsBeforeCertificateExpiresWhenFullLifetimeNoLongerFits()
    {
        options.WorkloadClients["test-client"] = new() { SecretHash = "synthetic-hash", Scopes = ["identity.validate"] };
        var passwords = new Mock<IPasswordHasher>();
        passwords.Setup(p => p.Verify("synthetic-hash", "synthetic-secret")).Returns(true);
        var clock = new SigningTestClock(Start.AddHours(1));
        using var keys = new SigningKeys(options, clock);
        var issuer = new TokenService(options, keys, passwords.Object, clock);
        clock.Current = Start.AddDays(1).AddMinutes(-5);

        Assert.That(keys.CanIssueTokens, Is.False);
        var error = Business.ThrowsBusiness(() => issuer.Issue("client_credentials", "test-client", "synthetic-secret", "identity.validate"));
        Assert.That(error.HttpStatus(), Is.EqualTo(503));
    }

    [Test]
    public void ValidTokenRetainsClaimsAlgorithmAndLifetimeAtCertificateBoundary()
    {
        var clock = new SigningTestClock(Start.AddDays(1).AddSeconds(-TokenService.AccessTokenLifetimeSeconds));
        using var keys = new SigningKeys(options, clock);
        var issuer = new TokenService(options, keys, Mock.Of<IPasswordHasher>(), clock);
        var identity = Guid.NewGuid();
        var session = Guid.NewGuid();

        var encoded = issuer.Issue(identity, session, clock.Current, clock.Current.AddSeconds(issuer.LifetimeSeconds));
        var token = new JwtSecurityTokenHandler().ReadJwtToken(encoded);

        Assert.Multiple(() =>
        {
            Assert.That(keys.CanIssueTokens, Is.True);
            Assert.That(token.Header.Alg, Is.EqualTo("RS256"));
            Assert.That(token.Header.Kid, Is.EqualTo(keys.Credentials.Key.KeyId));
            Assert.That(token.Subject, Is.EqualTo(identity.ToString("D")));
            Assert.That(token.Claims.Single(c => c.Type == "sid").Value, Is.EqualTo(session.ToString("D")));
            Assert.That(token.Audiences, Is.EquivalentTo(options.UserAudiences));
            Assert.That(token.ValidFrom, Is.EqualTo(clock.Current.UtcDateTime));
            Assert.That(token.ValidTo, Is.EqualTo(Start.AddDays(1).UtcDateTime));
        });
    }
}
