using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using NUnit.Framework;
using Vairas.Authentication.Business;
using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Tests;

[TestFixture, NonParallelizable]
public sealed class OidcTests
{
    private readonly TestEnvironment env = new();
    [OneTimeSetUp] public Task Start() => env.StartAsync();
    [OneTimeTearDown] public async Task Stop() => await env.DisposeAsync();
    private Task<OidcStartResult> Begin(string browser, string purpose = "Login", UserActor? actor = null) => env.Call(s =>
        s.BeginOidcAsync(new("https://issuer.test", "https://frontend.test/oidc/callback", purpose), actor, browser, TestEnvironment.Audit(), default));
    private Task<TokenPair> Complete(OidcStartResult start, string browser, string? subject = null, string mode = "valid")
    {
        var code = env.Oidc.Code(start.AuthorizationUrl, subject, mode);
        return env.Call(s => s.CompleteOidcAsync(new(code, start.State), browser, TestEnvironment.Audit(), default));
    }
    [Test]
    public async Task LoginCreatesAnExternalIdentityAndSingleUseBrowserBoundTransaction()
    {
        var browser = AuthPolicy.RandomSecret();
        var start = await Begin(browser);
        Assert.That(start.AuthorizationUrl, Does.Contain("code_challenge_method=S256").And.Contain("scope=openid"));
        var code = env.Oidc.Code(start.AuthorizationUrl);
        Business.ThrowsBusinessAsync(() => env.Call(s => s.CompleteOidcAsync(new(code, start.State), AuthPolicy.RandomSecret(), TestEnvironment.Audit(), default)));
        var pair = await env.Call(s => s.CompleteOidcAsync(new(code, start.State), browser, TestEnvironment.Audit(), default));
        Business.ThrowsBusinessAsync(() => env.Call(s => s.CompleteOidcAsync(new(code, start.State), browser, TestEnvironment.Audit(), default)));
        await using var db = env.OwnerDb();
        var identity = await db.Set<Identity>().SingleAsync(i => i.IdentityId == pair.IdentityId);
        Assert.That(identity.LoginEmail, Is.Null);
        Assert.That(await db.Set<PasswordCredential>().AnyAsync(c => c.IdentityId == pair.IdentityId), Is.False);
        Assert.That(await db.Set<ExternalIdentity>().AnyAsync(e => e.IdentityId == pair.IdentityId), Is.True);
    }
    [Test]
    public async Task ExactIssuerSubjectReturnsTheSameIdentityWithoutCreatingALocalPassword()
    {
        var subject = Guid.NewGuid().ToString("D");
        var firstBrowser = AuthPolicy.RandomSecret();
        var first = await Complete(await Begin(firstBrowser), firstBrowser, subject);
        var nextBrowser = AuthPolicy.RandomSecret();
        var second = await Complete(await Begin(nextBrowser), nextBrowser, subject);
        Assert.That(second.IdentityId, Is.EqualTo(first.IdentityId));
        Assert.That(second.SessionId, Is.Not.EqualTo(first.SessionId));
    }
    [Test]
    public async Task ExplicitLinkBindsOnlyTheAuthenticatedIdentity()
    {
        var (_, pair) = await env.UserAsync();
        var browser = AuthPolicy.RandomSecret();
        var subject = Guid.NewGuid().ToString("D");
        var linked = await Complete(await Begin(browser, "Link", new(pair.IdentityId, pair.SessionId)), browser, subject);
        Assert.That(linked.IdentityId, Is.EqualTo(pair.IdentityId));
        var loginBrowser = AuthPolicy.RandomSecret();
        Assert.That((await Complete(await Begin(loginBrowser), loginBrowser, subject)).IdentityId, Is.EqualTo(pair.IdentityId));
    }
    [Test]
    public async Task LinkRechecksItsOriginalSessionAfterTheRemoteExchange()
    {
        var (_, pair) = await env.UserAsync();
        var actor = new UserActor(pair.IdentityId, pair.SessionId);
        var browser = AuthPolicy.RandomSecret();
        var start = await Begin(browser, "Link", actor);
        await env.Call(s => s.RevokeAsync(actor, pair.SessionId, Guid.NewGuid(), TestEnvironment.Audit(), default));
        Business.ThrowsBusinessAsync(() => Complete(start, browser));
    }
    [Test]
    public async Task AnExternalBindingCannotBeTransferredToAnotherIdentity()
    {
        var browser = AuthPolicy.RandomSecret();
        var subject = Guid.NewGuid().ToString("D");
        await Complete(await Begin(browser), browser, subject);
        var (_, pair) = await env.UserAsync();
        var next = AuthPolicy.RandomSecret();
        var start = await Begin(next, "Link", new(pair.IdentityId, pair.SessionId));
        Assert.That(Business.ThrowsBusinessAsync(() => Complete(start, next, subject)).HttpStatus(), Is.EqualTo(409));
    }
    [TestCase("nonce", 401)]
    [TestCase("issuer", 401)]
    [TestCase("audience", 401)]
    [TestCase("expired", 401)]
    [TestCase("unavailable", 503)]
    public async Task InvalidProviderResponsesDoNotIssueVairasCredentials(string mode, int status)
    {
        var browser = AuthPolicy.RandomSecret();
        var start = await Begin(browser);
        Assert.That(Business.ThrowsBusinessAsync(() => Complete(start, browser, mode: mode)).HttpStatus(), Is.EqualTo(status));
        await using var db = env.OwnerDb();
        Assert.That((await db.Set<OidcRequest>().SingleAsync(r => r.StateDigest == AuthPolicy.Digest(start.State))).ConsumedAt, Is.Not.Null);
    }
    [Test]
    public async Task ProviderRedirectPurposeAndAnonymousLinkAreRestricted()
    {
        var browser = AuthPolicy.RandomSecret();
        Business.ThrowsBusinessAsync(() => Begin(browser, "Link"));
        Business.ThrowsBusinessAsync(() => Begin(browser, "Unexpected"));
        Business.ThrowsBusinessAsync(() => env.Call(s => s.BeginOidcAsync(new("https://evil.test", "https://frontend.test/oidc/callback", "Login"), null, browser, TestEnvironment.Audit(), default)));
        Business.ThrowsBusinessAsync(() => env.Call(s => s.BeginOidcAsync(new("https://issuer.test", "https://evil.test/oidc/callback", "Login"), null, browser, TestEnvironment.Audit(), default)));
    }
    [Test]
    public async Task ExpiredTransactionsCannotBeConsumed()
    {
        var browser = AuthPolicy.RandomSecret();
        var start = await Begin(browser);
        await using var db = env.OwnerDb();
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE oidc_request SET created_at=clock_timestamp()-interval '2 hours', expires_at=clock_timestamp()-interval '1 hour' WHERE state_digest={AuthPolicy.Digest(start.State)}");
        Business.ThrowsBusinessAsync(() => Complete(start, browser));
    }
    [Test]
    public async Task BrowserCallbackRequiresTheSecureCorrelationCookie()
    {
        using var response = await env.Client.PostAsJsonAsync("/api/v1/auth/oidc/requests", new { issuer = "https://issuer.test", redirectUri = "https://frontend.test/oidc/callback", purpose = "Login" });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
        var redirect = (await response.Content.ReadFromJsonAsync<OidcRedirect>())!;
        var cookie = response.Headers.GetValues("Set-Cookie").Single();
        Assert.That(cookie.ToLowerInvariant(), Does.Contain("secure").And.Contain("httponly").And.Contain("samesite=lax").And.Contain("path=/"));
        var state = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(new Uri(redirect.AuthorizationUrl).Query)["state"].ToString();
        var code = env.Oidc.Code(redirect.AuthorizationUrl);
        using var missing = await env.Client.PostAsJsonAsync("/api/v1/auth/oidc/callback", new { code, state });
        Assert.That(missing.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        using var callback = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/oidc/callback") { Content = JsonContent.Create(new { code, state }) };
        callback.Headers.Add("Cookie", cookie.Split(';')[0]);
        using var complete = await env.Client.SendAsync(callback);
        Assert.That(complete.StatusCode, Is.EqualTo(HttpStatusCode.OK), await complete.Content.ReadAsStringAsync());
    }
}
