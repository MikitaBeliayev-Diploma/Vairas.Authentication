using System.Text.Json;
using NUnit.Framework;
using Vairas.Authentication.Business;
using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Tests;

[TestFixture, Category("Unit")]
public sealed class AuthenticationBusinessTests
{
    private const string Email = "student@example.test";
    private const string Password = "a sufficiently long password";
    private const string Secret = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
    private const string Browser = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg";
    private MemoryAuthStore store = null!;
    private BusinessClock clock = null!;
    private FakePasswords passwords = null!;
    private FakeTokens tokens = null!;
    private FakeOidc oidc = null!;
    private FakeProtection protection = null!;
    private FakeThrottle throttle = null!;
    private AuthenticationService service = null!;
    private readonly AuditContext audit = new(Guid.Parse("11111111-1111-1111-1111-111111111111"));
    private static CancellationToken Ct => CancellationToken.None;

    [SetUp]
    public void SetUp()
    {
        store = new(); clock = new(); passwords = new(); tokens = new(); oidc = new(); protection = new(); throttle = new();
        service = new(store, passwords, tokens, protection, oidc, clock, throttle);
    }

    private Identity Identity(bool verified = true)
    {
        var identity = new Identity { IdentityId = Guid.NewGuid(), LoginEmail = Email, EmailVerifiedAt = verified ? clock.Now : null, CreatedAt = clock.Now };
        store.Seed(identity, new PasswordCredential { IdentityId = identity.IdentityId, PasswordHash = passwords.Hash(Password), ChangedAt = clock.Now });
        return identity;
    }
    private AuthSession Session(Guid identity, int seconds = 3600)
    {
        var session = new AuthSession { SessionId = Guid.NewGuid(), IdentityId = identity, CreatedAt = clock.Now, ExpiresAt = clock.Now.AddSeconds(seconds) };
        store.Seed(session, new RefreshToken { RefreshTokenId = Guid.NewGuid(), SessionId = session.SessionId, SecretDigest = AuthPolicy.Digest(Secret), ExpiresAt = session.ExpiresAt });
        return session;
    }
    private AccountChallenge Challenge(Identity identity, string purpose = "VerifyEmail")
    {
        var challenge = new AccountChallenge { ChallengeId = Guid.NewGuid(), IdentityId = identity.IdentityId, Purpose = purpose, LoginEmail = Email,
            CredentialRevision = identity.CredentialRevision, SecretDigest = AuthPolicy.Digest(Secret), CreatedAt = clock.Now, ExpiresAt = clock.Now.AddMinutes(15) };
        store.Seed(challenge);
        return challenge;
    }
    private static BusinessException Error(Func<Task> action, int status = 401)
    {
        var error = Business.ThrowsBusinessAsync(async () => await action())!;
        Assert.That(error.HttpStatus(), Is.EqualTo(status));
        return error;
    }
    private void Event(string type, string outcome)
    {
        var entry = store.All<SecurityEvent>().Single(x => x.EventType == type);
        Assert.Multiple(() => { Assert.That(entry.OutcomeCode, Is.EqualTo(outcome)); Assert.That(entry.CorrelationId, Is.EqualTo(audit.Id)); Assert.That(entry.OccurredAt, Is.EqualTo(clock.Now)); });
    }

    [Test]
    public async Task RegistrationCreatesCredentialVerificationAndProtectedDeliveryWithoutSession()
    {
        await service.RegisterAsync(new(" STUDENT@EXAMPLE.TEST ", Password), audit, Ct);
        var identity = store.One<Identity>(); var challenge = store.One<AccountChallenge>(); var delivery = store.One<ChallengeDelivery>();
        var mail = JsonSerializer.Deserialize<ChallengeMail>(protection.Unprotect("mail", delivery.ProtectedPayload!))!;
        Assert.Multiple(() =>
        {
            Assert.That(identity.LoginEmail, Is.EqualTo(Email)); Assert.That(identity.EmailVerifiedAt, Is.Null);
            Assert.That(store.One<PasswordCredential>().PasswordHash, Is.EqualTo(passwords.Hash(Password)));
            Assert.That(challenge.IdentityId, Is.EqualTo(identity.IdentityId)); Assert.That(challenge.ExpiresAt, Is.EqualTo(clock.Now.AddHours(24)));
            Assert.That(challenge.SecretDigest, Is.EqualTo(AuthPolicy.Digest(mail.Token))); Assert.That(challenge.SecretDigest, Is.Not.EqualTo(mail.Token));
            Assert.That(mail, Is.EqualTo(new ChallengeMail(Email, "VerifyEmail", mail.Token))); Assert.That(delivery.ChallengeId, Is.EqualTo(challenge.ChallengeId));
            Assert.That(store.All<AuthSession>(), Is.Empty); Assert.That(throttle.Checks.Single(), Is.EqualTo((Email, "registration")));
        });
        Event("Registered", "Accepted");
    }

    [Test]
    public async Task DuplicateAnonymousRegistrationDoesNotReplaceAccountOrPassword()
    {
        var existing = Identity();
        var reply = await service.RegisterAsync(new(Email, "another long password"), audit, Ct);
        Assert.Multiple(() => { Assert.That(reply, Is.EqualTo(new AcceptedResponse())); Assert.That(store.One<Identity>().IdentityId, Is.EqualTo(existing.IdentityId));
            Assert.That(store.One<PasswordCredential>().PasswordHash, Is.EqualTo(passwords.Hash(Password))); Assert.That(store.All<AccountChallenge>(), Is.Empty); Assert.That(store.All<SecurityEvent>(), Is.Empty); });
    }

    [Test]
    public async Task LoginCreatesSessionAndHashedRefreshCredentialWithBoundAccessToken()
    {
        var identity = Identity();
        var pair = await service.LoginAsync(new(Email, Password), audit, Ct);
        var session = store.One<AuthSession>(); var refresh = store.One<RefreshToken>();
        Assert.Multiple(() => { Assert.That(pair.IdentityId, Is.EqualTo(identity.IdentityId)); Assert.That(pair.SessionId, Is.EqualTo(session.SessionId));
            Assert.That(pair.TokenType, Is.EqualTo("Bearer")); Assert.That(pair.ExpiresIn, Is.EqualTo(300)); Assert.That(pair.AccessToken, Is.EqualTo("fake-access-token"));
            Assert.That(refresh.SecretDigest, Is.EqualTo(AuthPolicy.Digest(pair.RefreshToken))); Assert.That(refresh.ExpiresAt, Is.EqualTo(clock.Now.AddDays(7)));
            Assert.That(session.ExpiresAt, Is.EqualTo(clock.Now.AddDays(30))); Assert.That(tokens.Issued.Single(), Is.EqualTo((identity.IdentityId, session.SessionId, clock.Now, clock.Now.AddSeconds(300)))); });
        Event("SessionCreated", "Succeeded");
    }

    [TestCase("unknown"), TestCase("no-credential"), TestCase("wrong-password"), TestCase("unverified"), TestCase("disabled"), TestCase("revision-changed"), TestCase("removed")]
    public void LoginDeniesIneligibleCredentialsWithoutCreatingSessionAndCommitsAudit(string scenario)
    {
        var identity = scenario == "unknown" ? null : Identity(scenario != "unverified");
        if (scenario == "no-credential") store.Rows.Remove(store.One<PasswordCredential>());
        if (scenario == "disabled") identity!.SecurityState = "Disabled";
        if (scenario == "revision-changed") passwords.DuringVerify = () => store.One<Identity>().CredentialRevision++;
        if (scenario == "removed") passwords.DuringVerify = () => store.Rows.Remove(store.One<Identity>());
        Error(() => service.LoginAsync(new(Email, scenario == "wrong-password" ? "wrong" : Password), audit, Ct));
        Assert.Multiple(() => { Assert.That(store.All<AuthSession>(), Is.Empty); Assert.That(store.Committed, Is.EqualTo(2));
            Assert.That(passwords.DummyCalls, Is.EqualTo(scenario is "unknown" or "no-credential" ? 1 : 0)); });
        Event("Login", "Denied");
    }

    [Test]
    public void TokenIssuanceFailureRollsBackSessionAndRefreshWrites()
    {
        Identity(); tokens.Fail = true;
        Error(() => service.LoginAsync(new(Email, Password), audit, Ct), 503);
        Assert.Multiple(() => { Assert.That(store.All<AuthSession>(), Is.Empty); Assert.That(store.All<RefreshToken>(), Is.Empty); Assert.That(store.All<SecurityEvent>(), Is.Empty); });
    }

    [Test]
    public void ThrottleRejectsBeforeStoreMutation()
    {
        throttle.Reject = true;
        Error(() => service.RegisterAsync(new(Email, Password), audit, Ct), 429);
        Assert.That(store.Committed, Is.Zero);
    }

    [Test]
    public async Task RefreshDelegatesDigestsAndCorrelationToAtomicRotationAndCapsAccessToSessionExpiry()
    {
        var identity = Identity(); var session = Session(identity.IdentityId, 20);
        store.Rotate = (_, _, _, _) => new("Rotated", identity.IdentityId, session.SessionId);
        var pair = await service.RefreshAsync(new(Secret), audit, Ct);
        var call = store.Rotations.Single();
        Assert.Multiple(() => { Assert.That(call.OldDigest, Is.EqualTo(AuthPolicy.Digest(Secret))); Assert.That(call.NewId, Is.Not.EqualTo(Guid.Empty));
            Assert.That(call.NewDigest, Is.EqualTo(AuthPolicy.Digest(pair.RefreshToken))); Assert.That(call.NewDigest, Is.Not.EqualTo(call.OldDigest));
            Assert.That(call.Correlation, Is.EqualTo(audit.Id)); Assert.That(call.At, Is.EqualTo(clock.Now)); Assert.That(pair.ExpiresIn, Is.EqualTo(20)); Assert.That(pair.SessionId, Is.EqualTo(session.SessionId)); });
    }

    [TestCase("Replayed"), TestCase("Expired"), TestCase("Revoked"), TestCase("Unknown"), TestCase("missing-identity"), TestCase("missing-session")]
    public void RefreshRotationDenialsAreCommittedBeforeErrorAndNeverIssueAccess(string outcome)
    {
        store.Rotate = (_, _, _, _) => outcome switch
        {
            "missing-identity" => new("Rotated", null, Guid.NewGuid()),
            "missing-session" => new("Rotated", Guid.NewGuid(), Guid.NewGuid()),
            _ => new(outcome, null, null)
        };
        Error(() => service.RefreshAsync(new(Secret), audit, Ct));
        Assert.Multiple(() => { Assert.That(store.Committed, Is.EqualTo(1)); Assert.That(tokens.Issued, Is.Empty); });
    }

    [Test]
    public void ExpiredRotatedSessionDoesNotIssueAccess()
    {
        var identity = Identity(); var session = Session(identity.IdentityId, 0);
        store.Rotate = (_, _, _, _) => new("Rotated", identity.IdentityId, session.SessionId);
        Error(() => service.RefreshAsync(new(Secret), audit, Ct)); Assert.That(tokens.Issued, Is.Empty);
    }

    [Test]
    public async Task ReplacementChallengeInvalidatesOldTokenAndClearsOnlyPendingDeliverySecrets()
    {
        var identity = Identity(false); var old = Challenge(identity);
        store.Seed(new ChallengeDelivery { ChallengeId = old.ChallengeId, DeliveryId = Guid.NewGuid(), ProtectedPayload = "pending-secret" },
            new ChallengeDelivery { ChallengeId = old.ChallengeId, DeliveryId = Guid.NewGuid(), Status = "Sent", ProtectedPayload = "sent-secret" });
        await service.ChallengeAsync(new(Email, "VerifyEmail"), audit, Ct);
        Assert.Multiple(() => { Assert.That(store.All<AccountChallenge>().Single(x => x.ChallengeId == old.ChallengeId).InvalidatedAt, Is.EqualTo(clock.Now));
            Assert.That(store.All<ChallengeDelivery>().Single(x => x.Status == "Superseded").ProtectedPayload, Is.Null);
            Assert.That(store.All<ChallengeDelivery>().Single(x => x.Status == "Sent").ProtectedPayload, Is.EqualTo("sent-secret"));
            Assert.That(store.All<AccountChallenge>().Count(), Is.EqualTo(2)); });
        Event("ChallengeRequested", "Accepted");
    }

    [TestCase("unknown"), TestCase("disabled"), TestCase("verified"), TestCase("reset-without-credential")]
    public async Task IneligibleChallengeRequestIsIndistinguishableAndDoesNotQueueDelivery(string scenario)
    {
        if (scenario != "unknown")
        {
            var identity = Identity(); if (scenario == "disabled") identity.SecurityState = "Disabled";
            if (scenario == "reset-without-credential") store.Rows.Remove(store.One<PasswordCredential>());
        }
        var reply = await service.ChallengeAsync(new(Email, scenario == "reset-without-credential" ? "ResetPassword" : "VerifyEmail"), audit, Ct);
        Assert.Multiple(() => { Assert.That(reply, Is.EqualTo(new AcceptedResponse())); Assert.That(store.All<ChallengeDelivery>(), Is.Empty); });
    }

    [Test]
    public async Task ResetChallengeUsesShortExpiryAndDoesNotInvalidateConsumedChallenges()
    {
        var identity = Identity(); var old = Challenge(identity, "ResetPassword"); old.ConsumedAt = clock.Now.AddSeconds(-1);
        await service.ChallengeAsync(new(Email, "ResetPassword"), audit, Ct);
        Assert.Multiple(() => { Assert.That(store.All<AccountChallenge>().Single(x => x.ChallengeId == old.ChallengeId).InvalidatedAt, Is.Null);
            Assert.That(store.All<AccountChallenge>().Single(x => x.ChallengeId != old.ChallengeId).ExpiresAt, Is.EqualTo(clock.Now.AddMinutes(15))); });
    }

    [Test]
    public async Task EmailVerificationConsumesExactlyOnceAndNeverChangesPassword()
    {
        var identity = Identity(false); Challenge(identity);
        await service.CompleteAsync(new(Secret, null), audit, Ct);
        Assert.Multiple(() => { Assert.That(store.One<Identity>().EmailVerifiedAt, Is.EqualTo(clock.Now)); Assert.That(store.One<AccountChallenge>().ConsumedAt, Is.EqualTo(clock.Now));
            Assert.That(store.One<PasswordCredential>().PasswordHash, Is.EqualTo(passwords.Hash(Password))); });
        Error(() => service.CompleteAsync(new(Secret, null), audit, Ct)); Event("VerifyEmail", "Succeeded");
    }

    [Test]
    public async Task PasswordResetChangesRevisionRevokesAllFamiliesAndInvalidatesOtherChallenges()
    {
        var identity = Identity(); var challenge = Challenge(identity, "ResetPassword"); var session = Session(identity.IdentityId); var other = Session(identity.IdentityId);
        var verification = new AccountChallenge { ChallengeId = Guid.NewGuid(), IdentityId = identity.IdentityId, Purpose = "VerifyEmail", SecretDigest = "other" };
        store.Seed(verification);
        await service.CompleteAsync(new(Secret, "replacement password"), audit, Ct);
        Assert.Multiple(() => { Assert.That(store.One<Identity>().CredentialRevision, Is.EqualTo(2)); Assert.That(store.One<PasswordCredential>().PasswordHash, Is.EqualTo(passwords.Hash("replacement password")));
            Assert.That(store.All<AuthSession>().Select(x => x.SessionId), Is.EquivalentTo(new[] { session.SessionId, other.SessionId }));
            Assert.That(store.All<AuthSession>().All(x => x.RevokedAt == clock.Now && x.RevocationReason == "PasswordReset"), Is.True);
            Assert.That(store.All<RefreshToken>().All(x => x.RevokedAt == clock.Now), Is.True);
            Assert.That(store.All<AccountChallenge>().Single(x => x.ChallengeId == verification.ChallengeId).InvalidatedAt, Is.EqualTo(clock.Now));
            Assert.That(store.All<AccountChallenge>().Single(x => x.ChallengeId == challenge.ChallengeId).ConsumedAt, Is.EqualTo(clock.Now)); });
        Event("ResetPassword", "Succeeded");
    }

    [TestCase("unknown"), TestCase("disabled"), TestCase("expired"), TestCase("invalidated"), TestCase("consumed"), TestCase("revision"), TestCase("email")]
    public void UnusableChallengeIsDeniedWithoutMutation(string scenario)
    {
        var identity = Identity(false); var challenge = scenario == "unknown" ? null : Challenge(identity);
        switch (scenario)
        {
            case "disabled": identity.SecurityState = "Disabled"; break;
            case "expired": challenge!.ExpiresAt = clock.Now; break;
            case "invalidated": challenge!.InvalidatedAt = clock.Now; break;
            case "consumed": challenge!.ConsumedAt = clock.Now.AddMinutes(-1); break;
            case "revision": identity.CredentialRevision++; break;
            case "email": identity.LoginEmail = "changed@example.test"; break;
        }
        Error(() => service.CompleteAsync(new(Secret, null), audit, Ct));
        Assert.Multiple(() => { Assert.That(store.One<Identity>().EmailVerifiedAt, Is.Null); Assert.That(store.All<SecurityEvent>(), Is.Empty); });
    }

    [TestCase("VerifyEmail", true, 400), TestCase("ResetPassword", false, 400), TestCase("ResetPassword", true, 401)]
    public void CompletionRejectsPurposePayloadMismatchOrAbsentPasswordCredential(string purpose, bool hasPassword, int status)
    {
        var identity = Identity(false); Challenge(identity, purpose);
        if (purpose == "ResetPassword" && hasPassword) store.Rows.Remove(store.One<PasswordCredential>());
        Error(() => service.CompleteAsync(new(Secret, hasPassword ? Password : null), audit, Ct), status);
        Assert.That(store.One<AccountChallenge>().ConsumedAt, Is.Null);
    }

    [TestCase(10, true), TestCase(100, true), TestCase(0, false)]
    public async Task ValidationReturnsExactPairAndAdmissionCappedBySessionExpiry(int seconds, bool active)
    {
        var identity = Identity(); var session = Session(identity.IdentityId, seconds);
        var result = await service.ValidateAsync(new(identity.IdentityId, session.SessionId), Ct);
        Assert.Multiple(() => { Assert.That(result.Active, Is.EqualTo(active)); Assert.That(result.IdentityId, Is.EqualTo(identity.IdentityId)); Assert.That(result.SessionId, Is.EqualTo(session.SessionId));
            Assert.That(result.ValidUntil, Is.EqualTo(clock.Now.AddSeconds(active ? Math.Min(seconds, 30) : 30))); });
    }

    [Test]
    public async Task ValidationDeniesAnotherIdentitysSession()
    {
        var identity = Identity(); var other = Session(Guid.NewGuid());
        Assert.That((await service.ValidateAsync(new(identity.IdentityId, other.SessionId), Ct)).Active, Is.False);
    }

    [Test]
    public async Task SelfLogoutRevokesFamilyAndCanReplayExactOperationWithoutRepeatingAudit()
    {
        var identity = Identity(); var session = Session(identity.IdentityId); var actor = new UserActor(identity.IdentityId, session.SessionId); var operation = Guid.NewGuid();
        var first = await service.RevokeAsync(actor, session.SessionId, operation, audit, Ct);
        var second = await service.RevokeAsync(actor, session.SessionId, operation, audit, Ct);
        Assert.Multiple(() => { Assert.That(second, Is.EqualTo(first)); Assert.That(store.One<AuthSession>().RevocationReason, Is.EqualTo("UserRevoked"));
            Assert.That(store.One<RefreshToken>().RevokedAt, Is.EqualTo(clock.Now)); Assert.That(store.All<AuthOperation>().Count(), Is.EqualTo(1)); Assert.That(store.All<SecurityEvent>().Count(), Is.EqualTo(1)); });
        Event("SessionRevoked", "Succeeded");
    }

    [Test]
    public async Task RevocationNeverPrecedesTheSessionOrTokenWrittenByAFasterClock()
    {
        // Another instance (or the database rotation) stamped these facts 90 s ahead of this instance's clock.
        var identity = Identity(); var session = Session(identity.IdentityId); var ahead = clock.Now.AddSeconds(90);
        session.CreatedAt = ahead; var token = store.One<RefreshToken>(); token.CreatedAt = ahead;
        await service.RevokeAsync(new UserActor(identity.IdentityId, session.SessionId), session.SessionId, Guid.NewGuid(), audit, Ct);
        // The fake commits copies; read the committed rows back.
        Assert.Multiple(() => { Assert.That(store.One<AuthSession>().RevokedAt, Is.EqualTo(ahead)); Assert.That(store.One<RefreshToken>().RevokedAt, Is.EqualTo(ahead)); });
    }

    [Test]
    public async Task RevocationOperationCannotBeReboundToAnotherTarget()
    {
        var identity = Identity(); var caller = Session(identity.IdentityId); var target = Session(identity.IdentityId); var actor = new UserActor(identity.IdentityId, caller.SessionId); var operation = Guid.NewGuid();
        await service.RevokeAsync(actor, target.SessionId, operation, audit, Ct);
        Error(() => service.RevokeAsync(actor, caller.SessionId, operation, audit, Ct), 409);
        Assert.That(store.All<AuthSession>().Single(x => x.SessionId == caller.SessionId).RevokedAt, Is.Null);
    }

    [TestCase(false), TestCase(true)]
    public void UnknownOrForeignTargetPersistsAndReplaysSameNotFoundOutcome(bool foreign)
    {
        var identity = Identity(); var caller = Session(identity.IdentityId); var target = foreign ? Session(Guid.NewGuid()).SessionId : Guid.NewGuid();
        var operation = Guid.NewGuid(); var actor = new UserActor(identity.IdentityId, caller.SessionId);
        Error(() => service.RevokeAsync(actor, target, operation, audit, Ct), 404);
        Error(() => service.RevokeAsync(actor, target, operation, audit, Ct), 404);
        Assert.Multiple(() => { Assert.That(store.One<AuthOperation>().OutcomeStatus, Is.EqualTo(404)); Assert.That(store.All<SecurityEvent>().Count(), Is.EqualTo(1)); });
        Event("SessionRevocationRejected", "NotFound");
    }

    [Test]
    public void RevokedCallerCannotCreateNewRevocationOperation()
    {
        var identity = Identity(); var caller = Session(identity.IdentityId); caller.RevokedAt = clock.Now; caller.RevocationReason = "PasswordReset";
        Error(() => service.RevokeAsync(new(identity.IdentityId, caller.SessionId), caller.SessionId, Guid.NewGuid(), audit, Ct));
        Assert.That(store.All<AuthOperation>(), Is.Empty);
    }

    private Task<OidcStartResult> Begin(string purpose = "Login", UserActor? actor = null) => service.BeginOidcAsync(new("https://issuer.test", "https://client.test/callback", purpose), actor, Browser, audit, Ct);
    private Task<TokenPair> Callback(string state, string browser = Browser) => service.CompleteOidcAsync(new("provider-code", state), browser, audit, Ct);

    [Test]
    public async Task OidcLoginPersistsBrowserPkceNonceBindingAndCreatesExternalIdentityWithoutEmail()
    {
        var started = await Begin(); var pending = store.One<OidcRequest>();
        Assert.Multiple(() => { Assert.That(started.AuthorizationUrl, Does.Contain(started.State)); Assert.That(pending.StateDigest, Is.EqualTo(AuthPolicy.Digest(started.State)));
            Assert.That(pending.BrowserDigest, Is.EqualTo(AuthPolicy.Digest(Browser))); Assert.That(pending.ExpiresAt, Is.EqualTo(clock.Now.AddMinutes(10))); });
        var pair = await Callback(started.State);
        Assert.Multiple(() => { Assert.That(store.One<Identity>().LoginEmail, Is.Null); Assert.That(store.One<ExternalIdentity>().IdentityId, Is.EqualTo(pair.IdentityId));
            Assert.That(store.One<AuthSession>().AuthMethod, Is.EqualTo("Oidc")); Assert.That(oidc.ExchangedSecrets, Is.EqualTo(new OidcSecrets(oidc.Authorization!.Value.Verifier, oidc.Authorization.Value.Nonce)));
            Assert.That(store.One<OidcRequest>().ConsumedAt, Is.EqualTo(clock.Now)); });
        Error(() => Callback(started.State)); Assert.That(oidc.Exchanges, Is.EqualTo(1));
    }

    [Test]
    public async Task ExistingExternalSubjectReturnsSameIdentityWithoutDuplicateLink()
    {
        var identity = Identity(); store.Seed(new ExternalIdentity { ExternalIdentityId = Guid.NewGuid(), IdentityId = identity.IdentityId, Issuer = oidc.Subject.Issuer, Subject = oidc.Subject.Subject });
        var started = await Begin(); var pair = await Callback(started.State);
        Assert.Multiple(() => { Assert.That(pair.IdentityId, Is.EqualTo(identity.IdentityId)); Assert.That(store.All<Identity>().Count(), Is.EqualTo(1)); Assert.That(store.All<ExternalIdentity>().Count(), Is.EqualTo(1)); });
    }

    [TestCase("expired"), TestCase("browser"), TestCase("missing"), TestCase("nonce")]
    public async Task OidcInvalidCorrelationIsDeniedBeforeProviderExchange(string scenario)
    {
        var started = await Begin();
        if (scenario == "expired") clock.Now = clock.Now.AddMinutes(10);
        if (scenario == "nonce") store.One<OidcRequest>().NonceDigest = AuthPolicy.Digest("tampered");
        Error(() => Callback(scenario == "missing" ? Secret : started.State, scenario == "browser" ? Secret : Browser));
        Assert.Multiple(() => { Assert.That(oidc.Exchanges, Is.Zero); Assert.That(store.All<AuthSession>(), Is.Empty); });
    }

    [Test]
    public async Task OidcProviderFailureLeavesClaimConsumedSoCodeCannotBeReplayed()
    {
        var started = await Begin(); oidc.ExchangeFailure = AuthErrors.Dependency();
        Error(() => Callback(started.State), 503); Error(() => Callback(started.State));
        Assert.Multiple(() => { Assert.That(store.One<OidcRequest>().ConsumedAt, Is.EqualTo(clock.Now)); Assert.That(oidc.Exchanges, Is.EqualTo(1)); Assert.That(store.All<Identity>(), Is.Empty); });
    }

    [TestCase("wrong-issuer"), TestCase("empty-subject"), TestCase("long-subject"), TestCase("disabled")]
    public async Task OidcUntrustedSubjectOrDisabledIdentityCannotCreateSession(string scenario)
    {
        if (scenario == "disabled")
        {
            var identity = Identity(); identity.SecurityState = "Disabled";
            store.Seed(new ExternalIdentity { ExternalIdentityId = Guid.NewGuid(), IdentityId = identity.IdentityId, Issuer = oidc.Subject.Issuer, Subject = oidc.Subject.Subject });
        }
        else oidc.Subject = scenario switch { "wrong-issuer" => new("https://other.test", "subject"), "empty-subject" => new("https://issuer.test", ""), _ => new("https://issuer.test", new string('x', 256)) };
        var started = await Begin(); Error(() => Callback(started.State)); Assert.That(store.All<AuthSession>(), Is.Empty);
    }

    [TestCase(false), TestCase(true)]
    public async Task ExplicitOidcLinkBindsToCurrentIdentityAndDoesNotDuplicateExistingBinding(bool alreadyLinked)
    {
        var identity = Identity(); var caller = Session(identity.IdentityId);
        if (alreadyLinked) store.Seed(new ExternalIdentity { ExternalIdentityId = Guid.NewGuid(), IdentityId = identity.IdentityId, Issuer = oidc.Subject.Issuer, Subject = oidc.Subject.Subject });
        var started = await Begin("Link", new(identity.IdentityId, caller.SessionId)); var pair = await Callback(started.State);
        Assert.Multiple(() => { Assert.That(pair.IdentityId, Is.EqualTo(identity.IdentityId)); Assert.That(store.All<ExternalIdentity>().Count(), Is.EqualTo(1)); Assert.That(store.One<OidcRequest>().LinkSessionId, Is.EqualTo(caller.SessionId)); });
    }

    [TestCase("foreign-subject"), TestCase("caller-revoked"), TestCase("identity-disabled")]
    public async Task OidcLinkRechecksCurrentSessionAndRejectsSubjectOwnedByAnotherIdentity(string scenario)
    {
        var identity = Identity(); var caller = Session(identity.IdentityId); var started = await Begin("Link", new(identity.IdentityId, caller.SessionId));
        if (scenario == "foreign-subject") store.Seed(new ExternalIdentity { ExternalIdentityId = Guid.NewGuid(), IdentityId = Guid.NewGuid(), Issuer = oidc.Subject.Issuer, Subject = oidc.Subject.Subject });
        if (scenario == "caller-revoked") store.One<AuthSession>().RevokedAt = clock.Now;
        if (scenario == "identity-disabled") store.One<Identity>().SecurityState = "Disabled";
        Error(() => Callback(started.State), scenario == "foreign-subject" ? 409 : 401);
        Assert.That(store.All<AuthSession>().Count(), Is.EqualTo(1));
    }

    [Test]
    public void OidcLinkRequiresActiveLocalActor()
    {
        Error(() => Begin("Link")); var identity = Identity(); var caller = Session(identity.IdentityId, 0);
        Error(() => Begin("Link", new(identity.IdentityId, caller.SessionId))); Assert.That(store.All<OidcRequest>(), Is.Empty);
    }

    [Test]
    public void MalformedRequestsAreRejectedBeforeStartingTransactions()
    {
        Error(() => service.RegisterAsync(new("bad-email", Password), audit, Ct), 400);
        Error(() => service.LoginAsync(new(Email, ""), audit, Ct), 400);
        Error(() => service.RefreshAsync(new("short"), audit, Ct), 400);
        Error(() => service.ChallengeAsync(new(Email, "Other"), audit, Ct), 400);
        Error(() => service.CompleteAsync(new(Secret, "short"), audit, Ct), 400);
        Error(() => service.ValidateAsync(new(Guid.Empty, Guid.NewGuid()), Ct), 400);
        Error(() => service.RevokeAsync(new(Guid.NewGuid(), Guid.NewGuid()), Guid.Empty, Guid.NewGuid(), audit, Ct), 400);
        Error(() => service.BeginOidcAsync(new("https://issuer.test", "https://client.test/callback", "Other"), null, Browser, audit, Ct), 400);
        Error(() => service.CompleteOidcAsync(new("", Secret), Browser, audit, Ct), 400);
        Assert.That(store.Committed, Is.Zero);
    }
}
