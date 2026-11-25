using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Moq;
using NUnit.Framework;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration;
using Vairas.Authentication.Security;
using Vairas.Authentication.Configuration.Options;
namespace Vairas.Authentication.Tests;

[TestFixture, Category("Unit")]
public sealed partial class TokenExchangeTests
{
    private const string GrantType = "urn:ietf:params:oauth:token-type:access_token";
    private const string Secret = "synthetic-token-exchange-secret-32-characters";
    private string file = null!; private SigningKeys keys = null!; private PasswordHasher passwords = null!;
    private AuthOptions options = null!; private TokenService signer = null!; private TokenExchange exchange = null!;
    private Mock<IAuthenticationService> auth = null!;
    private readonly Guid identity = Guid.NewGuid(), session = Guid.NewGuid(), school = Guid.NewGuid();
    [SetUp]
    public void Setup()
    {
        file = Path.Combine(Path.GetTempPath(), "vairas-exchange-" + Guid.NewGuid().ToString("N") + ".pfx");
        using var rsa = RSA.Create(2048); var request = new CertificateRequest("CN=Synthetic Exchange", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1)); File.WriteAllBytes(file, cert.Export(X509ContentType.Pfx));
        options = new() { SigningCertificatePath = file }; options.Delegation.Enabled = true;
        passwords = new(); var hash = passwords.Hash(Secret);
        foreach (var name in new[] { "chat-backend", "mcp-server", "other" }) options.WorkloadClients[name] = new() { SecretHash = hash, AllowTokenExchange = true };
        keys = new(options); signer = new(options, keys, passwords, TimeProvider.System);
        auth = new(); auth.Setup(a => a.ValidateAsync(It.IsAny<SessionValidationRequest>(), It.IsAny<CancellationToken>())).ReturnsAsync((SessionValidationRequest r, CancellationToken _) => new SessionValidationResult(true, r.IdentityId, r.SessionId, DateTimeOffset.UtcNow.AddSeconds(30)));
        exchange = new(options, keys, passwords, signer, auth.Object, TimeProvider.System);
    }
    [TearDown] public void Cleanup() { keys.Dispose(); passwords.Dispose(); File.Delete(file); }
    private string User() => signer.Issue(identity, session, DateTimeOffset.UtcNow.AddSeconds(-1), DateTimeOffset.UtcNow.AddMinutes(10));
    private Task<ExchangeTokenResponse> First(string? subject = null, string scope = "mcp.context.read mcp.get_my_enrollments") => exchange.IssueAsync("chat-backend", Secret, subject ?? User(), GrantType, null, options.Delegation.McpResource, scope, school.ToString(), default);
    [Test]
    public async Task Two_hops_issue_distinct_single_audience_tokens_with_immutable_school_and_actor_chain()
    {
        var first = await First(); var a = new JwtSecurityTokenHandler().ReadJwtToken(first.AccessToken);
        Assert.That(a.Audiences, Is.EqualTo(new[] { options.Delegation.McpResource })); Assert.That(a.Subject, Is.EqualTo(identity.ToString()));
        Assert.That(first.ExpiresIn, Is.InRange(1, 30)); Assert.That(a.Claims.Single(c => c.Type == "school_id").Value, Is.EqualTo(school.ToString()));
        var second = await exchange.IssueAsync("mcp-server", Secret, first.AccessToken, GrantType, GrantType, options.Delegation.Resources["school-management"], "mcp.get_my_enrollments", school.ToString(), default);
        var b = new JwtSecurityTokenHandler().ReadJwtToken(second.AccessToken);
        Assert.That(b.Audiences, Is.EqualTo(new[] { "vairas-school-management" })); Assert.That(second.AccessToken, Is.Not.EqualTo(first.AccessToken));
        Assert.That(b.Claims.Single(c => c.Type == "act").Value, Does.Contain("mcp-server").And.Contain("chat-backend")); Assert.That(b.ValidTo, Is.LessThanOrEqualTo(a.ValidTo));
    }
    [TestCase("disabled")][TestCase("secret")][TestCase("client")][TestCase("target")][TestCase("scope")][TestCase("type")][TestCase("expired")][TestCase("signature")][TestCase("revoked")]
    public void Invalid_initial_exchange_is_rejected(string variant)
    {
        var client = "chat-backend"; var secret = Secret; var target = options.Delegation.McpResource; var scope = "mcp.get_my_enrollments"; var type = GrantType; var user = User();
        switch (variant)
        {
            case "disabled": options.Delegation.Enabled = false; break;
            case "secret": secret = "wrong"; break; case "client": client = "other"; break;
            case "target": target = "https://attacker.invalid/"; break; case "scope": scope = "scheduling.mcp.write"; break; case "type": type = "id_token"; break;
            case "expired": user = signer.Issue(identity, session, DateTimeOffset.UtcNow.AddSeconds(-30), DateTimeOffset.UtcNow.AddSeconds(-10)); break;
            case "signature": var parts = user.Split('.'); parts[2] = new string('A', parts[2].Length); user = string.Join('.', parts); break;
            case "revoked": auth.Setup(a => a.ValidateAsync(It.IsAny<SessionValidationRequest>(), It.IsAny<CancellationToken>())).ReturnsAsync(new SessionValidationResult(false, identity, session, DateTimeOffset.UtcNow.AddSeconds(30))); break;
        }
        Business.ThrowsBusinessAsync(() => exchange.IssueAsync(client, secret, user, type, null, target, scope, school.ToString(), default));
    }
    [TestCase("school")][TestCase("scope")][TestCase("owner")][TestCase("third-hop")]
    public async Task Second_hop_cannot_change_school_escalate_scope_or_extend_the_chain(string variant)
    {
        var first = await First(); var subject = first.AccessToken; var tenant = school; var scope = "mcp.get_my_enrollments"; var target = options.Delegation.Resources["school-management"];
        switch (variant)
        {
            case "school": tenant = Guid.NewGuid(); break; case "scope": scope = "mcp.get_my_lessons"; break;
            case "owner": target = options.Delegation.Resources["scheduling"]; break;
            case "third-hop": subject = (await exchange.IssueAsync("mcp-server", Secret, subject, GrantType, null, target, scope, school.ToString(), default)).AccessToken; break;
        }
        Business.ThrowsBusinessAsync(() => exchange.IssueAsync("mcp-server", Secret, subject, GrantType, null, target, scope, tenant.ToString(), default));
    }
}
