using System.Text.Json;
using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

public sealed class AuthenticationService(IAuthStore store, IPasswordHasher passwords, IUserTokenIssuer tokens,
    ISecretProtector protection, IOidcProvider oidc, TimeProvider clock, IAccountThrottle throttle) : IAuthenticationService
{
    public async Task<AcceptedResponse> RegisterAsync(CredentialsRequest request, AuditContext audit, CancellationToken ct)
    {
        var email = AuthPolicy.Email(request.Email);
        AuthPolicy.Password(request.Password, true);
        throttle.Check(email, "registration");
        var hash = passwords.Hash(request.Password);
        return await store.ExecuteAsync(async tx =>
        {
            await tx.LockAsync("email:" + email, ct);
            var identity = await tx.IdentityByEmailAsync(email, ct);
            var now = AuthPolicy.Now(clock);
            if (identity is null)
            {
                identity = new Identity { IdentityId = Guid.NewGuid(), LoginEmail = email, CreatedAt = now };
                tx.Add(identity);
                tx.Add(new PasswordCredential { IdentityId = identity.IdentityId, PasswordHash = hash, ChangedAt = now });
                await NewChallengeAsync(tx, identity, "VerifyEmail", now, ct);
                Event(tx, identity.IdentityId, null, "Registered", "Accepted", audit, now);
            }
            // An anonymous duplicate must never replace an existing password or claim its identity.
            return new AcceptedResponse();
        }, ct);
    }

    public async Task<TokenPair> LoginAsync(CredentialsRequest request, AuditContext audit, CancellationToken ct)
    {
        var email = AuthPolicy.Email(request.Email);
        AuthPolicy.Password(request.Password, false);
        throttle.Check(email, "login");
        // Expensive password work does not hold a transaction or a database lock.
        var snapshot = await store.ExecuteAsync(async tx =>
        {
            var i = await tx.IdentityByEmailAsync(email, ct);
            var c = i is null ? null : await tx.CredentialAsync(i.IdentityId, ct);
            return (Identity: i?.IdentityId, Revision: i?.CredentialRevision, Hash: c?.PasswordHash);
        }, ct);
        var valid = false;
        if (snapshot.Hash is null) passwords.DummyVerify(request.Password);
        else valid = passwords.Verify(snapshot.Hash, request.Password);
        var result = await store.ExecuteAsync(async tx =>
        {
            var now = AuthPolicy.Now(clock);
            if (snapshot.Identity is null)
            {
                Event(tx, null, null, "Login", "Denied", audit, now);
                return Decision<TokenPair>.Deny();
            }
            await tx.LockAsync("identity:" + snapshot.Identity.Value.ToString("D"), ct);
            var identity = await tx.IdentityAsync(snapshot.Identity.Value, ct);
            if (!valid || identity is not { SecurityState: "Enabled", EmailVerifiedAt: not null } ||
                identity.CredentialRevision != snapshot.Revision)
            {
                Event(tx, identity?.IdentityId, null, "Login", "Denied", audit, now);
                return Decision<TokenPair>.Deny();
            }
            return Decision<TokenPair>.Allow(NewSession(tx, identity, "Password", audit, now));
        }, ct);
        return result.Get();
    }

    public async Task<TokenPair> RefreshAsync(RefreshRequest request, AuditContext audit, CancellationToken ct)
    {
        AuthPolicy.Secret(request.RefreshToken);
        var secret = AuthPolicy.RandomSecret();
        var result = await store.ExecuteAsync(async tx =>
        {
            var rotation = await tx.RotateAsync(AuthPolicy.Digest(request.RefreshToken), Guid.NewGuid(), AuthPolicy.Digest(secret), audit.Id, AuthPolicy.Now(clock), ct);
            if (rotation is not { Outcome: "Rotated", IdentityId: not null, SessionId: not null }) return Decision<TokenPair>.Deny();
            var session = await tx.SessionAsync(rotation.SessionId.Value, ct);
            return session is null ? Decision<TokenPair>.Deny() : Decision<TokenPair>.Allow(Pair(session, secret, AuthPolicy.Now(clock)));
        }, ct);
        // The denial is thrown only after committing the SQL function's replay revocation and audit.
        return result.Get();
    }

    public async Task<AcceptedResponse> ChallengeAsync(ChallengeRequest request, AuditContext audit, CancellationToken ct)
    {
        var email = AuthPolicy.Email(request.Email);
        if (request.Purpose is not ("VerifyEmail" or "ResetPassword")) throw AuthErrors.Invalid();
        throttle.Check(email, "challenge");
        return await store.ExecuteAsync(async tx =>
        {
            await tx.LockAsync("email:" + email, ct);
            var identity = await tx.IdentityByEmailAsync(email, ct);
            if (identity is { SecurityState: "Enabled" })
            {
                await tx.LockAsync("identity:" + identity.IdentityId.ToString("D"), ct);
                // Reload after obtaining the identity lock: a password reset may have changed its revision.
                identity = await tx.IdentityAsync(identity.IdentityId, ct);
                var now = AuthPolicy.Now(clock);
                var credential = await tx.CredentialAsync(identity!.IdentityId, ct);
                if (identity.SecurityState == "Enabled" &&
                    (request.Purpose == "VerifyEmail" ? identity.EmailVerifiedAt is null : credential is not null))
                {
                    await NewChallengeAsync(tx, identity, request.Purpose, now, ct);
                    Event(tx, identity.IdentityId, null, "ChallengeRequested", "Accepted", audit, now);
                }
            }
            return new AcceptedResponse();
        }, ct);
    }

    public async Task<AcceptedResponse> CompleteAsync(ChallengeCompletionRequest request, AuditContext audit, CancellationToken ct)
    {
        AuthPolicy.Secret(request.ChallengeToken);
        if (request.NewPassword is not null) AuthPolicy.Password(request.NewPassword, true);
        var newHash = request.NewPassword is null ? null : passwords.Hash(request.NewPassword);
        var result = await store.ExecuteAsync(async tx =>
        {
            var challenge = await tx.ChallengeAsync(AuthPolicy.Digest(request.ChallengeToken), ct);
            if (challenge is null) return Decision<AcceptedResponse>.Deny();
            await tx.LockAsync("identity:" + challenge.IdentityId.ToString("D"), ct);
            // Transaction reads are refreshed by the store after lock acquisition.
            challenge = await tx.ChallengeAsync(AuthPolicy.Digest(request.ChallengeToken), ct);
            var identity = await tx.IdentityAsync(challenge!.IdentityId, ct);
            var now = AuthPolicy.Now(clock);
            if (identity is not { SecurityState: "Enabled" } || challenge.ConsumedAt is not null || challenge.InvalidatedAt is not null ||
                challenge.ExpiresAt <= now || challenge.CredentialRevision != identity.CredentialRevision || challenge.LoginEmail != identity.LoginEmail)
                return Decision<AcceptedResponse>.Deny();
            if (challenge.Purpose == "VerifyEmail")
            {
                if (request.NewPassword is not null) return Decision<AcceptedResponse>.Deny(AuthErrors.Invalid());
                identity.EmailVerifiedAt ??= now;
            }
            else
            {
                if (newHash is null) return Decision<AcceptedResponse>.Deny(AuthErrors.Invalid());
                var credential = await tx.CredentialAsync(identity.IdentityId, ct);
                if (credential is null) return Decision<AcceptedResponse>.Deny();
                credential.PasswordHash = newHash;
                credential.ChangedAt = now;
                identity.CredentialRevision++;
                foreach (var session in await tx.SessionsAsync(identity.IdentityId, ct))
                    await RevokeFamilyAsync(tx, session, "PasswordReset", now, ct);
                foreach (var purpose in new[] { "VerifyEmail", "ResetPassword" })
                    foreach (var other in await tx.ChallengesAsync(identity.IdentityId, purpose, ct))
                        if (other.ChallengeId != challenge.ChallengeId && other.ConsumedAt is null) other.InvalidatedAt ??= now;
            }
            challenge.ConsumedAt = now;
            Event(tx, identity.IdentityId, null, challenge.Purpose, "Succeeded", audit, now);
            return Decision<AcceptedResponse>.Allow(new());
        }, ct);
        return result.Get();
    }

    public Task<SessionValidationResult> ValidateAsync(SessionValidationRequest request, CancellationToken ct)
    {
        if (request.IdentityId == Guid.Empty || request.SessionId == Guid.Empty) throw AuthErrors.Invalid();
        return store.ExecuteAsync(async tx =>
        {
            var identity = await tx.IdentityAsync(request.IdentityId, ct);
            var session = await tx.SessionAsync(request.SessionId, ct);
            var now = AuthPolicy.Now(clock);
            var active = AuthPolicy.Active(identity, session, now);
            var until = active && session!.ExpiresAt < now.AddSeconds(30) ? session.ExpiresAt : now.AddSeconds(30);
            return new SessionValidationResult(active, request.IdentityId, request.SessionId, until);
        }, ct);
    }

    public async Task<SessionRevocation> RevokeAsync(UserActor actor, Guid sessionId, Guid operationId, AuditContext audit, CancellationToken ct)
    {
        if (sessionId == Guid.Empty || operationId == Guid.Empty) throw AuthErrors.Invalid();
        var result = await store.ExecuteAsync(async tx =>
        {
            await tx.LockAsync("operation:" + operationId.ToString("D"), ct);
            await tx.LockAsync("identity:" + actor.IdentityId.ToString("D"), ct);
            var operation = await tx.OperationAsync(operationId, ct);
            var fingerprint = AuthPolicy.RevocationFingerprint(actor.IdentityId, sessionId);
            var identity = await tx.IdentityAsync(actor.IdentityId, ct);
            var caller = await tx.SessionAsync(actor.SessionId, ct);
            var now = AuthPolicy.Now(clock);
            if (operation is not null && operation.Fingerprint != fingerprint) return Decision<SessionRevocation>.Deny(AuthErrors.Conflict());
            var active = AuthPolicy.Active(identity, caller, now);
            var ownLogoutReplay = operation is { OutcomeStatus: 200 } && identity is { SecurityState: "Enabled" } && caller is not null &&
                caller.IdentityId == actor.IdentityId && caller.ExpiresAt > now && caller.RevocationReason == "UserRevoked" &&
                operation.SourceSessionId == actor.SessionId && operation.TargetSessionId == actor.SessionId;
            if (!active && !ownLogoutReplay) return Decision<SessionRevocation>.Deny();
            if (operation is not null) return operation.OutcomeStatus == 200 ? Decision<SessionRevocation>.Allow(new(sessionId)) :
                Decision<SessionRevocation>.Deny(new NotFoundException("NOT_FOUND", "The session was not found."));
            var target = await tx.SessionAsync(sessionId, ct);
            if (target is null || target.IdentityId != actor.IdentityId)
            {
                tx.Add(new AuthOperation { OperationId = operationId, IdentityId = actor.IdentityId, SourceSessionId = actor.SessionId,
                    TargetSessionId = sessionId, Fingerprint = fingerprint, OutcomeStatus = 404, RecordedAt = now });
                Event(tx, actor.IdentityId, actor.SessionId, "SessionRevocationRejected", "NotFound", audit, now);
                return Decision<SessionRevocation>.Deny(new NotFoundException("NOT_FOUND", "The session was not found."));
            }
            await RevokeFamilyAsync(tx, target, "UserRevoked", now, ct);
            tx.Add(new AuthOperation { OperationId = operationId, IdentityId = actor.IdentityId, SourceSessionId = actor.SessionId,
                TargetSessionId = sessionId, Fingerprint = fingerprint, RecordedAt = now });
            Event(tx, actor.IdentityId, target.SessionId, "SessionRevoked", "Succeeded", audit, now);
            return Decision<SessionRevocation>.Allow(new(sessionId));
        }, ct);
        return result.Get();
    }

    public async Task<OidcStartResult> BeginOidcAsync(OidcStartRequest request, UserActor? actor, string browserSecret, AuditContext audit, CancellationToken ct)
    {
        if (request.Purpose is not ("Login" or "Link")) throw AuthErrors.Invalid();
        AuthPolicy.Secret(browserSecret);
        oidc.Validate(request.Issuer, request.RedirectUri);
        if (request.Purpose == "Link" && actor is null) throw AuthErrors.Denied();
        var state = AuthPolicy.RandomSecret();
        var nonce = AuthPolicy.RandomSecret();
        var verifier = AuthPolicy.RandomSecret();
        var url = await oidc.AuthorizationUrlAsync(request.Issuer, request.RedirectUri, state, nonce, verifier, ct);
        var result = await store.ExecuteAsync(async tx =>
        {
            var now = AuthPolicy.Now(clock);
            if (request.Purpose == "Link")
            {
                await tx.LockAsync("identity:" + actor!.IdentityId.ToString("D"), ct);
                if (!AuthPolicy.Active(await tx.IdentityAsync(actor.IdentityId, ct), await tx.SessionAsync(actor.SessionId, ct), now))
                    return Decision<OidcStartResult>.Deny();
            }
            tx.Add(new OidcRequest { RequestId = Guid.NewGuid(), Purpose = request.Purpose, Issuer = request.Issuer,
                StateDigest = AuthPolicy.Digest(state), BrowserDigest = AuthPolicy.Digest(browserSecret), NonceDigest = AuthPolicy.Digest(nonce),
                PkceVerifierCiphertext = protection.Protect("oidc", JsonSerializer.Serialize(new OidcSecrets(verifier, nonce))),
                RedirectUri = request.RedirectUri, LinkIdentityId = request.Purpose == "Link" ? actor!.IdentityId : null,
                LinkSessionId = request.Purpose == "Link" ? actor!.SessionId : null, CreatedAt = now, ExpiresAt = now.AddMinutes(10) });
            return Decision<OidcStartResult>.Allow(new(url, state));
        }, ct);
        return result.Get();
    }

    public async Task<TokenPair> CompleteOidcAsync(OidcCallbackRequest request, string browserSecret, AuditContext audit, CancellationToken ct)
    {
        AuthPolicy.Secret(request.State);
        AuthPolicy.Secret(browserSecret);
        if (string.IsNullOrWhiteSpace(request.Code) || request.Code.Length > 4096) throw AuthErrors.Invalid();
        var claimed = await store.ExecuteAsync(async tx =>
        {
            await tx.LockAsync("oidc:" + AuthPolicy.Digest(request.State), ct);
            var saved = await tx.OidcAsync(AuthPolicy.Digest(request.State), ct);
            var now = AuthPolicy.Now(clock);
            if (saved is null || saved.ConsumedAt is not null || saved.ExpiresAt <= now ||
                !AuthPolicy.EqualDigest(saved.BrowserDigest, AuthPolicy.Digest(browserSecret))) return Decision<OidcRequest>.Deny();
            saved.ConsumedAt = now;
            return Decision<OidcRequest>.Allow(saved);
        }, ct);
        // Claim before remote I/O; a lost/failed exchange requires a new request rather than code replay.
        var transaction = claimed.Get();
        var secrets = JsonSerializer.Deserialize<OidcSecrets>(protection.Unprotect("oidc", transaction.PkceVerifierCiphertext))!;
        if (!AuthPolicy.EqualDigest(transaction.NonceDigest, AuthPolicy.Digest(secrets.Nonce))) throw AuthErrors.Denied();
        oidc.Validate(transaction.Issuer, transaction.RedirectUri);
        var subject = await oidc.ExchangeAsync(transaction.Issuer, transaction.RedirectUri, request.Code, secrets, ct);
        if (subject.Issuer != transaction.Issuer || string.IsNullOrEmpty(subject.Subject) || subject.Subject.Length > 255) throw AuthErrors.Denied();
        var result = await store.ExecuteAsync(async tx =>
        {
            await tx.LockAsync("external:" + subject.Issuer + "|" + subject.Subject, ct);
            var external = await tx.ExternalAsync(subject.Issuer, subject.Subject, ct);
            var now = AuthPolicy.Now(clock);
            Identity? identity;
            if (transaction.Purpose == "Link")
            {
                await tx.LockAsync("identity:" + transaction.LinkIdentityId!.Value.ToString("D"), ct);
                identity = await tx.IdentityAsync(transaction.LinkIdentityId.Value, ct);
                var session = await tx.SessionAsync(transaction.LinkSessionId!.Value, ct);
                if (!AuthPolicy.Active(identity, session, now)) return Decision<TokenPair>.Deny();
                if (external is not null && external.IdentityId != identity!.IdentityId) return Decision<TokenPair>.Deny(AuthErrors.Conflict());
            }
            else if (external is not null)
            {
                await tx.LockAsync("identity:" + external.IdentityId.ToString("D"), ct);
                identity = await tx.IdentityAsync(external.IdentityId, ct);
                if (identity is not { SecurityState: "Enabled" }) return Decision<TokenPair>.Deny();
            }
            else
            {
                // Provider email is never used as a local identity binding or a trusted login address.
                identity = new Identity { IdentityId = Guid.NewGuid(), CreatedAt = now };
                tx.Add(identity);
            }
            if (external is null) tx.Add(new ExternalIdentity { ExternalIdentityId = Guid.NewGuid(), IdentityId = identity!.IdentityId,
                Issuer = subject.Issuer, Subject = subject.Subject, LinkedAt = now });
            return Decision<TokenPair>.Allow(NewSession(tx, identity!, "Oidc", audit, now));
        }, ct);
        return result.Get();
    }

    private async Task NewChallengeAsync(IAuthTransaction tx, Identity identity, string purpose, DateTimeOffset now, CancellationToken ct)
    {
        foreach (var old in await tx.ChallengesAsync(identity.IdentityId, purpose, ct))
        {
            if (old.ConsumedAt is not null || old.InvalidatedAt is not null) continue;
            old.InvalidatedAt = now;
            foreach (var delivery in await tx.DeliveriesAsync(old.ChallengeId, ct))
                if (delivery.Status == "Pending") { delivery.Status = "Superseded"; delivery.ProtectedPayload = null; }
        }
        var secret = AuthPolicy.RandomSecret();
        var expires = purpose == "VerifyEmail" ? now.AddHours(24) : now.AddMinutes(15);
        var challenge = new AccountChallenge { ChallengeId = Guid.NewGuid(), IdentityId = identity.IdentityId, Purpose = purpose,
            LoginEmail = identity.LoginEmail!, CredentialRevision = identity.CredentialRevision, SecretDigest = AuthPolicy.Digest(secret),
            CreatedAt = now, ExpiresAt = expires };
        tx.Add(challenge);
        tx.Add(new ChallengeDelivery { DeliveryId = Guid.NewGuid(), ChallengeId = challenge.ChallengeId,
            ProtectedPayload = protection.Protect("mail", JsonSerializer.Serialize(new ChallengeMail(identity.LoginEmail!, purpose, secret))),
            CreatedAt = now, NextAttemptAt = now, ExpiresAt = expires });
    }
    private TokenPair NewSession(IAuthTransaction tx, Identity identity, string method, AuditContext audit, DateTimeOffset now)
    {
        var session = new AuthSession { SessionId = Guid.NewGuid(), IdentityId = identity.IdentityId, AuthMethod = method,
            CreatedAt = now, ExpiresAt = now.AddDays(30) };
        var secret = AuthPolicy.RandomSecret();
        tx.Add(session);
        tx.Add(new RefreshToken { RefreshTokenId = Guid.NewGuid(), SessionId = session.SessionId, SecretDigest = AuthPolicy.Digest(secret),
            CreatedAt = now, ExpiresAt = now.AddDays(7) });
        Event(tx, identity.IdentityId, session.SessionId, "SessionCreated", "Succeeded", audit, now);
        return Pair(session, secret, now);
    }
    private TokenPair Pair(AuthSession session, string secret, DateTimeOffset now)
    {
        var seconds = (int)Math.Min(tokens.LifetimeSeconds, (session.ExpiresAt - now).TotalSeconds);
        if (seconds <= 0) throw AuthErrors.Denied();
        return new(tokens.Issue(session.IdentityId, session.SessionId, now, now.AddSeconds(seconds)), secret, "Bearer", seconds, session.IdentityId, session.SessionId);
    }
    private static async Task RevokeFamilyAsync(IAuthTransaction tx, AuthSession session, string reason, DateTimeOffset now, CancellationToken ct)
    {
        // Never stamp a revocation before the fact it revokes, even if another instance's clock ran ahead (ck_*_revoked_at >= created_at).
        session.RevokedAt ??= now > session.CreatedAt ? now : session.CreatedAt;
        session.RevocationReason ??= reason;
        foreach (var token in await tx.FamilyAsync(session.SessionId, ct)) token.RevokedAt ??= now > token.CreatedAt ? now : token.CreatedAt;
    }
    private static void Event(IAuthTransaction tx, Guid? identity, Guid? session, string type, string outcome, AuditContext audit, DateTimeOffset now) =>
        tx.Add(new SecurityEvent { EventId = Guid.NewGuid(), IdentityId = identity, SessionId = session, EventType = type,
            OutcomeCode = outcome, CorrelationId = audit.Id, OccurredAt = now });
}
