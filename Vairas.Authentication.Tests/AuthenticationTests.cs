using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi;
using Npgsql;
using NUnit.Framework;
using Vairas.Authentication.Business;
using Vairas.Authentication.Domain;
using Vairas.Authentication.Security;

namespace Vairas.Authentication.Tests;

[TestFixture, NonParallelizable]
public sealed class AuthenticationTests
{
    private readonly TestEnvironment env = new();
    [OneTimeSetUp] public Task Start() => env.StartAsync();
    [OneTimeTearDown] public async Task Stop() => await env.DisposeAsync();

    [Test]
    public async Task MigrationsPreserveCanonicalSchemaAndCanBeRepeated()
    {
        await using var db = env.OwnerDb();
        await db.Database.MigrateAsync();
        Assert.That(db.Database.HasPendingModelChanges(), Is.False);
        Assert.That((await db.Database.GetAppliedMigrationsAsync()).Count(), Is.EqualTo(3));
        var rotation = await db.Database.SqlQueryRaw<string>("SELECT p.oid::regprocedure::text AS \"Value\" FROM pg_proc p WHERE p.proname='auth_rotate_refresh'").ToListAsync();
        Assert.That(rotation, Is.EqualTo(new[] { "auth_rotate_refresh(text,uuid,text,uuid,timestamp with time zone)" }));
        var count = await db.Database.SqlQueryRaw<int>("SELECT count(*)::integer AS \"Value\" FROM information_schema.columns WHERE table_schema='public' AND table_name IN ('identity','password_credential','external_identity','auth_session','refresh_token','account_challenge','oidc_request','security_event')").SingleAsync();
        Assert.That(count, Is.EqualTo(59));
    }

    [Test]
    public async Task RegistrationIsGenericAndCannotReplaceAnExistingCredential()
    {
        var email = Guid.NewGuid().ToString("N") + "@example.test";
        var first = await env.Call(s => s.RegisterAsync(new(email.ToUpperInvariant(), TestEnvironment.Password), TestEnvironment.Audit(), default));
        var second = await env.Call(s => s.RegisterAsync(new(email, "Attacker passphrase 2026"), TestEnvironment.Audit(), default));
        Assert.That(second, Is.EqualTo(first));
        await using var db = env.OwnerDb();
        var identity = await db.Set<Identity>().SingleAsync(i => i.LoginEmail == email);
        var credential = await db.Set<PasswordCredential>().SingleAsync(c => c.IdentityId == identity.IdentityId);
        using var hasher = new PasswordHasher();
        Assert.That(hasher.Verify(credential.PasswordHash, TestEnvironment.Password), Is.True);
        Assert.That(credential.PasswordHash, Does.StartWith("$argon2id$"));
        var mail = await env.MailAsync(email);
        var challenge = await db.Set<AccountChallenge>().SingleAsync(c => c.IdentityId == identity.IdentityId);
        var delivery = await db.Set<ChallengeDelivery>().SingleAsync(d => d.ChallengeId == challenge.ChallengeId);
        Assert.That(challenge.SecretDigest, Is.EqualTo(AuthPolicy.Digest(mail.Token)));
        Assert.That(delivery.ProtectedPayload, Does.Not.Contain(mail.Token));
        Business.ThrowsBusinessAsync(() => env.Call(s => s.LoginAsync(new(email, TestEnvironment.Password), TestEnvironment.Audit(), default)));
    }

    [Test]
    public async Task VerifiedLoginIssuesIdentityBoundJwtAndDigestOnlyRefresh()
    {
        var (_, pair) = await env.UserAsync();
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(pair.AccessToken);
        Assert.Multiple(() =>
        {
            Assert.That(jwt.Header.Alg, Is.EqualTo("RS256"));
            Assert.That(jwt.Subject, Is.EqualTo(pair.IdentityId.ToString("D")));
            Assert.That(jwt.Claims.Single(c => c.Type == "sid").Value, Is.EqualTo(pair.SessionId.ToString("D")));
            Assert.That(jwt.Audiences, Does.Contain("vairas-user-management").And.Contain("vairas-authentication"));
            Assert.That(pair.ExpiresIn, Is.EqualTo(900));
        });
        await using var db = env.OwnerDb();
        var token = await db.Set<RefreshToken>().SingleAsync(t => t.SessionId == pair.SessionId);
        var session = await db.Set<AuthSession>().SingleAsync(s => s.SessionId == pair.SessionId);
        Assert.That(token.SecretDigest, Is.EqualTo(AuthPolicy.Digest(pair.RefreshToken)));
        Assert.That(token.ExpiresAt - token.CreatedAt, Is.EqualTo(TimeSpan.FromDays(7)));
        Assert.That(session.ExpiresAt - session.CreatedAt, Is.EqualTo(TimeSpan.FromDays(30)));
    }

    [Test]
    public async Task RefreshReuseCommitsWholeFamilyRevocationBeforeReturningDenial()
    {
        var (_, original) = await env.UserAsync();
        var next = await env.Call(s => s.RefreshAsync(new(original.RefreshToken), TestEnvironment.Audit(), default));
        Assert.That(next.SessionId, Is.EqualTo(original.SessionId));
        Assert.That(next.RefreshToken, Is.Not.EqualTo(original.RefreshToken));
        Business.ThrowsBusinessAsync(() => env.Call(s => s.RefreshAsync(new(original.RefreshToken), TestEnvironment.Audit(), default)));
        await using var db = env.OwnerDb();
        var session = await db.Set<AuthSession>().SingleAsync(s => s.SessionId == original.SessionId);
        Assert.That(session.RevocationReason, Is.EqualTo("RefreshReuse"));
        Assert.That(await db.Set<RefreshToken>().Where(t => t.SessionId == original.SessionId).AllAsync(t => t.RevokedAt != null), Is.True);
        Assert.That(await db.Set<SecurityEvent>().AnyAsync(e => e.SessionId == original.SessionId && e.EventType == "RefreshReuse"), Is.True);
        Business.ThrowsBusinessAsync(() => env.Call(s => s.RefreshAsync(new(next.RefreshToken), TestEnvironment.Audit(), default)));
    }

    [Test]
    public async Task RotationAndReuseRevocationHoldTemporalConstraintsWhenLoginClockRanAhead()
    {
        // Deterministic regression for app/DB clock skew: the login instance's clock was two minutes ahead.
        var (_, original) = await env.UserAsync();
        await TestEnvironment.SqlAsync(env.OwnerConnection,
            $"UPDATE auth_session SET created_at=created_at+interval '2 minutes' WHERE session_id='{original.SessionId}';" +
            $"UPDATE refresh_token SET created_at=created_at+interval '2 minutes' WHERE session_id='{original.SessionId}';");
        var next = await env.Call(s => s.RefreshAsync(new(original.RefreshToken), TestEnvironment.Audit(), default));
        Business.ThrowsBusinessAsync(() => env.Call(s => s.RefreshAsync(new(original.RefreshToken), TestEnvironment.Audit(), default)));
        await using var db = env.OwnerDb();
        var tokens = await db.Set<RefreshToken>().Where(t => t.SessionId == original.SessionId).ToListAsync();
        var session = await db.Set<AuthSession>().SingleAsync(s => s.SessionId == next.SessionId);
        Assert.Multiple(() =>
        {
            Assert.That(tokens, Has.Count.EqualTo(2));
            Assert.That(tokens.All(t => t.ConsumedAt is null || t.ConsumedAt >= t.CreatedAt), Is.True);
            Assert.That(tokens.All(t => t.RevokedAt >= t.CreatedAt), Is.True);
            Assert.That(session.RevocationReason, Is.EqualTo("RefreshReuse"));
        });
    }

    [Test]
    public async Task ConcurrentRefreshCannotCreateTwoLiveSuccessors()
    {
        var (_, original) = await env.UserAsync();
        async Task<bool> Attempt()
        {
            try { await env.Call(s => s.RefreshAsync(new(original.RefreshToken), TestEnvironment.Audit(), default)); return true; }
            catch (UnauthorizedException) { return false; }
        }
        var results = await Task.WhenAll(Attempt(), Attempt());
        Assert.That(results.Count(x => x), Is.EqualTo(1));
        var admission = await env.Call(s => s.ValidateAsync(new(original.IdentityId, original.SessionId), default));
        Assert.That(admission.Active, Is.False);
        await using var db = env.OwnerDb();
        Assert.That(await db.Set<RefreshToken>().CountAsync(t => t.SessionId == original.SessionId), Is.EqualTo(2));
    }

    [Test]
    public async Task PasswordResetRevokesAllSessionsAndRejectsOldPasswordAndChallenge()
    {
        var (email, first) = await env.UserAsync();
        var second = await env.Call(s => s.LoginAsync(new(email, TestEnvironment.Password), TestEnvironment.Audit(), default));
        await env.Call(s => s.ChallengeAsync(new(email, "ResetPassword"), TestEnvironment.Audit(), default));
        var mail = await env.MailAsync(email, "ResetPassword");
        Business.ThrowsBusinessAsync(() => env.Call(s => s.CompleteAsync(new(mail.Token, null), TestEnvironment.Audit(), default)));
        await env.Call(s => s.CompleteAsync(new(mail.Token, "Replacement passphrase 2026"), TestEnvironment.Audit(), default));
        foreach (var pair in new[] { first, second })
        {
            Assert.That((await env.Call(s => s.ValidateAsync(new(pair.IdentityId, pair.SessionId), default))).Active, Is.False);
            Business.ThrowsBusinessAsync(() => env.Call(s => s.RefreshAsync(new(pair.RefreshToken), TestEnvironment.Audit(), default)));
        }
        Business.ThrowsBusinessAsync(() => env.Call(s => s.CompleteAsync(new(mail.Token, "Different passphrase 2026"), TestEnvironment.Audit(), default)));
        Business.ThrowsBusinessAsync(() => env.Call(s => s.LoginAsync(new(email, TestEnvironment.Password), TestEnvironment.Audit(), default)));
        Assert.That((await env.Call(s => s.LoginAsync(new(email, "Replacement passphrase 2026"), TestEnvironment.Audit(), default))).IdentityId, Is.EqualTo(first.IdentityId));
    }

    [Test]
    public async Task NewChallengeInvalidatesItsPredecessorAndDoesNotDiscloseUnknownAccounts()
    {
        var (email, pair) = await env.UserAsync();
        var accepted = await env.Call(s => s.ChallengeAsync(new(email, "ResetPassword"), TestEnvironment.Audit(), default));
        var old = await env.MailAsync(email, "ResetPassword");
        await env.Call(s => s.ChallengeAsync(new(email, "ResetPassword"), TestEnvironment.Audit(), default));
        var current = await env.MailAsync(email, "ResetPassword");
        Assert.That(current.Token, Is.Not.EqualTo(old.Token));
        Business.ThrowsBusinessAsync(() => env.Call(s => s.CompleteAsync(new(old.Token, TestEnvironment.Password), TestEnvironment.Audit(), default)));
        var unknown = await env.Call(s => s.ChallengeAsync(new(Guid.NewGuid().ToString("N") + "@example.test", "ResetPassword"), TestEnvironment.Audit(), default));
        Assert.That(unknown, Is.EqualTo(accepted));
        await using var db = env.OwnerDb();
        Assert.That(await db.Set<ChallengeDelivery>().AnyAsync(d => d.Status == "Superseded" && d.ProtectedPayload == null), Is.True);
        Assert.That((await env.Call(s => s.ValidateAsync(new(pair.IdentityId, pair.SessionId), default))).Active, Is.True);
    }

    [TestCase("Expired")]
    [TestCase("Revision")]
    [TestCase("Disabled")]
    public async Task StaleOrDisabledChallengesCannotChangeCredentials(string reason)
    {
        var (email, pair) = await env.UserAsync();
        await env.Call(s => s.ChallengeAsync(new(email, "ResetPassword"), TestEnvironment.Audit(), default));
        var mail = await env.MailAsync(email, "ResetPassword");
        await using var db = env.OwnerDb();
        if (reason == "Expired") await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE account_challenge SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE identity_id={pair.IdentityId} AND purpose='ResetPassword'");
        if (reason == "Revision") await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE identity SET credential_revision=credential_revision+1 WHERE identity_id={pair.IdentityId}");
        if (reason == "Disabled") await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE identity SET security_state='Disabled' WHERE identity_id={pair.IdentityId}");
        Business.ThrowsBusinessAsync(() => env.Call(s => s.CompleteAsync(new(mail.Token, "Replacement passphrase 2026"), TestEnvironment.Audit(), default)));
    }

    [Test]
    public async Task RevocationRetriesReturnTheSameResultAndCannotChangeTargetOrIdentity()
    {
        var (_, pair) = await env.UserAsync();
        var actor = new UserActor(pair.IdentityId, pair.SessionId);
        var operation = Guid.NewGuid();
        var first = await env.Call(s => s.RevokeAsync(actor, pair.SessionId, operation, TestEnvironment.Audit(), default));
        var retry = await env.Call(s => s.RevokeAsync(actor, pair.SessionId, operation, TestEnvironment.Audit(), default));
        Assert.That(retry, Is.EqualTo(first));
        var error = Business.ThrowsBusinessAsync(() => env.Call(s => s.RevokeAsync(actor, Guid.NewGuid(), operation, TestEnvironment.Audit(), default)));
        Assert.That(error.HttpStatus(), Is.EqualTo(409));
        Business.ThrowsBusinessAsync(() => env.Call(s => s.RevokeAsync(actor, pair.SessionId, Guid.NewGuid(), TestEnvironment.Audit(), default)));
        await using var db = env.OwnerDb();
        Assert.That(await db.Set<AuthOperation>().CountAsync(o => o.OperationId == operation), Is.EqualTo(1));
    }

    [Test]
    public async Task CannotRevokeAnotherIdentitySessionOrValidateItsBinding()
    {
        var (_, first) = await env.UserAsync();
        var (_, second) = await env.UserAsync();
        var result = await env.Call(s => s.ValidateAsync(new(first.IdentityId, second.SessionId), default));
        Assert.That(result, Is.EqualTo(new SessionValidationResult(false, first.IdentityId, second.SessionId, result.ValidUntil)));
        Assert.That(result.ValidUntil, Is.GreaterThan(DateTimeOffset.UtcNow));
        Assert.That(Business.ThrowsBusinessAsync(() => env.Call(s => s.RevokeAsync(new(first.IdentityId, first.SessionId), second.SessionId, Guid.NewGuid(), TestEnvironment.Audit(), default))).HttpStatus(), Is.EqualTo(404));
    }
    [Test]
    public async Task RejectedRevocationRetainsItsBindingAndCannotBeRetargeted()
    {
        var (_, pair) = await env.UserAsync();
        var actor = new UserActor(pair.IdentityId, pair.SessionId);
        var absent = Guid.NewGuid(); var operation = Guid.NewGuid();
        Assert.That(Business.ThrowsBusinessAsync(() => env.Call(s => s.RevokeAsync(actor, absent, operation, TestEnvironment.Audit(), default))).HttpStatus(), Is.EqualTo(404));
        Assert.That(Business.ThrowsBusinessAsync(() => env.Call(s => s.RevokeAsync(actor, absent, operation, TestEnvironment.Audit(), default))).HttpStatus(), Is.EqualTo(404));
        Assert.That(Business.ThrowsBusinessAsync(() => env.Call(s => s.RevokeAsync(actor, pair.SessionId, operation, TestEnvironment.Audit(), default))).HttpStatus(), Is.EqualTo(409));
        Assert.That((await env.Call(s => s.ValidateAsync(new(pair.IdentityId, pair.SessionId), default))).Active, Is.True);
    }

    [TestCase("UPDATE security_event SET outcome_code='Tampered'")]
    [TestCase("DELETE FROM identity")]
    [TestCase("TRUNCATE auth_session CASCADE")]
    [TestCase("CREATE TEMP TABLE leaked_secret(x text)")]
    [TestCase("UPDATE auth_operation SET fingerprint=repeat('0',64)")]
    public void RestrictedRuntimeCannotRewriteAuditOrDeleteData(string sql)
    {
        var exception = Assert.ThrowsAsync<PostgresException>(() => TestEnvironment.SqlAsync(env.RuntimeConnection, sql));
        Assert.That(exception!.SqlState, Is.EqualTo("42501"));
    }

    [Test]
    public async Task HttpApiExercisesRegistrationVerificationLoginAndLogout()
    {
        var email = Guid.NewGuid().ToString("N") + "@example.test";
        using var registration = await env.Client.PostAsJsonAsync("/api/v1/auth/registrations", new { email, password = TestEnvironment.Password });
        Assert.That(registration.StatusCode, Is.EqualTo(HttpStatusCode.Accepted), await registration.Content.ReadAsStringAsync());
        Assert.That(registration.Headers.CacheControl?.NoStore, Is.True);
        var mail = await env.MailAsync(email);
        using var completion = await env.Client.PostAsJsonAsync("/api/v1/auth/challenges/completion", new { challengeToken = mail.Token });
        Assert.That(completion.StatusCode, Is.EqualTo(HttpStatusCode.OK), await completion.Content.ReadAsStringAsync());
        using var login = await env.Client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = TestEnvironment.Password });
        Assert.That(login.StatusCode, Is.EqualTo(HttpStatusCode.OK), await login.Content.ReadAsStringAsync());
        var pair = (await login.Content.ReadFromJsonAsync<TokenPair>())!;
        using var revoke = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/auth/sessions/{pair.SessionId}/revocation");
        revoke.Headers.Authorization = new("Bearer", pair.AccessToken); revoke.Headers.Add("Idempotency-Key", Guid.NewGuid().ToString());
        using var response = await env.Client.SendAsync(revoke);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
    }

    [TestCase("{\"email\":\"x@example.test\",\"password\":\"x\",\"role\":\"Admin\"}")]
    [TestCase("{\"email\":\"x@example.test\",\"email\":\"y@example.test\",\"password\":\"valid passphrase 2026\"}")]
    [TestCase("{\"Email\":\"x@example.test\",\"password\":\"valid passphrase 2026\"}")]
    public async Task InvalidJsonShapesAreRejectedWithoutReflectingSecrets(string payload)
    {
        using var response = await env.Client.PostAsync("/api/v1/auth/registrations", new StringContent(payload, Encoding.UTF8, "application/json"));
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        var body = await response.Content.ReadAsStringAsync();
        Assert.That(body, Does.Not.Contain("passphrase").And.Not.Contain("x@example.test"));
        Assert.That(response.Content.Headers.ContentType!.MediaType, Is.EqualTo("application/problem+json"));
    }

    [Test]
    public async Task WorkloadScopesAndAudiencesAreEnforced()
    {
        var (_, pair) = await env.UserAsync();
        var token = await env.WorkloadTokenAsync(scope: "identity.validate school.profile-provisioning confirmations.validate");
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        Assert.That(jwt.Subject, Is.EqualTo("user-management"));
        Assert.That(jwt.Audiences, Does.Contain("vairas-authentication-internal").And.Not.Contain("vairas-user-management"));
        using var request = new HttpRequestMessage(HttpMethod.Post, "/internal/v1/sessions/validate") { Content = JsonContent.Create(new SessionValidationRequest(pair.IdentityId, pair.SessionId)) };
        request.Headers.Authorization = new("Bearer", token);
        using var response = await env.Client.SendAsync(request);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
        Assert.That((await response.Content.ReadFromJsonAsync<SessionValidationResult>())!.Active, Is.True);
        using var denied = await env.Client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string> {
            ["grant_type"] = "client_credentials", ["client_id"] = "reader", ["client_secret"] = env.WorkloadSecret, ["scope"] = "identity.validate" }));
        Assert.That(denied.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        using var wrongAudience = new HttpRequestMessage(HttpMethod.Post, "/internal/v1/sessions/validate") { Content = JsonContent.Create(new SessionValidationRequest(pair.IdentityId, pair.SessionId)) };
        wrongAudience.Headers.Authorization = new("Bearer", pair.AccessToken);
        using var wrong = await env.Client.SendAsync(wrongAudience);
        Assert.That(wrong.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task DiscoveryAndJwksNeverPublishPrivateKeyOrUnsupportedLoginGrants()
    {
        var discovery = await env.Client.GetStringAsync("/.well-known/openid-configuration");
        Assert.That(discovery, Does.Contain("client_credentials").And.Not.Contain("authorization_endpoint").And.Not.Contain("password"));
        using var jwks = JsonDocument.Parse(await env.Client.GetStringAsync("/.well-known/jwks.json"));
        var key = jwks.RootElement.GetProperty("keys")[0];
        Assert.That(key.GetProperty("alg").GetString(), Is.EqualTo("RS256"));
        Assert.That(key.TryGetProperty("d", out _), Is.False);
        Assert.That((await env.Client.GetAsync("/health/ready")).StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task UntrustedBrowserOriginAndMalformedBearerAreDenied()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login") { Content = JsonContent.Create(new { email = "unknown@example.test", password = TestEnvironment.Password }) };
        request.Headers.Add("Origin", "https://evil.test");
        using var response = await env.Client.SendAsync(request);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
        using var malformed = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/auth/sessions/{Guid.NewGuid()}/revocation");
        malformed.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid");
        using var denied = await env.Client.SendAsync(malformed);
        Assert.That(denied.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }
    [Test]
    public async Task ALocalhostHostHeaderCannotBypassTheTlsBoundary()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "http://localhost:7100/api/v1/auth/login")
        {
            Content = JsonContent.Create(new { email = "unknown@example.test", password = TestEnvironment.Password })
        };
        // TestServer has no loopback remote address. The untrusted Host header must not establish one.
        request.Headers.Host = "localhost";
        using var response = await env.Client.SendAsync(request);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
        Assert.That(await response.Content.ReadAsStringAsync(), Does.Contain("TLS_REQUIRED"));
    }
    [Test]
    public async Task GeneratedOpenApiHasAllCanonicalOperationsAndPassesMicrosoftValidation()
    {
        var json = await env.Client.GetStringAsync("/openapi/v1.json");
        var parsed = OpenApiDocument.Parse(json, "json");
        Assert.That(parsed.Diagnostic!.Errors, Is.Empty);
        var document = parsed.Document ?? throw new AssertionException("OpenAPI document was not parsed.");
        var errors = document.Validate(ValidationRuleSet.GetDefaultRuleSet()).ToArray();
        Assert.That(errors, Is.Empty, string.Join(Environment.NewLine, errors.Select(e => e.ToString())));
        Assert.That(document.Paths.Count, Is.EqualTo(13));
        Assert.That(document.Paths.ContainsKey("/.well-known/jwks.json"), Is.True);
        Assert.That(document.Components!.Schemas!["CredentialsRequest"].Properties!["password"].WriteOnly, Is.True);
        Assert.That(document.Paths["/internal/v1/sessions/validate"].Operations![HttpMethod.Post].Security![0].Single().Value, Does.Contain("identity.validate"));
        Assert.That(document.Paths["/api/v1/auth/sessions/{sessionId}/revocation"].Operations![HttpMethod.Post].Parameters!.Single(p => p.Name == "Idempotency-Key").Required, Is.True);
        Directory.CreateDirectory(Path.Combine(TestEnvironment.Root, ".cache"));
        await File.WriteAllTextAsync(Path.Combine(TestEnvironment.Root, ".cache", "authentication.openapi.json"), json);
    }
}
