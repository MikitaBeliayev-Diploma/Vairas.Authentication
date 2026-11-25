using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

public interface IAuthTransaction
{
    Task LockAsync(string key, CancellationToken ct);
    Task<Identity?> IdentityAsync(Guid id, CancellationToken ct);
    Task<Identity?> IdentityByEmailAsync(string email, CancellationToken ct);
    Task<PasswordCredential?> CredentialAsync(Guid id, CancellationToken ct);
    Task<AuthSession?> SessionAsync(Guid id, CancellationToken ct);
    Task<List<AuthSession>> SessionsAsync(Guid identity, CancellationToken ct);
    Task<List<RefreshToken>> FamilyAsync(Guid session, CancellationToken ct);
    Task<AccountChallenge?> ChallengeAsync(string digest, CancellationToken ct);
    Task<List<AccountChallenge>> ChallengesAsync(Guid identity, string purpose, CancellationToken ct);
    Task<List<ChallengeDelivery>> DeliveriesAsync(Guid challenge, CancellationToken ct);
    Task<OidcRequest?> OidcAsync(string digest, CancellationToken ct);
    Task<ExternalIdentity?> ExternalAsync(string issuer, string subject, CancellationToken ct);
    Task<AuthOperation?> OperationAsync(Guid id, CancellationToken ct);
    Task<RotationResult> RotateAsync(string oldDigest, Guid newId, string newDigest, Guid correlation, DateTimeOffset at, CancellationToken ct);
    void Add<T>(T entity) where T : class;
}
