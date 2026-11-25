using System.Text.Json;
using Vairas.Authentication.Business;
using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Tests;

// A transaction copies its working set and publishes it only on success. In particular,
// Decision.Deny is committed, while an exception rolls back. No persistence or HTTP adapter runs.
internal sealed class MemoryAuthStore : IAuthStore
{
    public List<object> Rows { get; private set; } = [];
    public List<string> Locks { get; } = [];
    public int Committed { get; private set; }
    public Action<int>? BeforeExecute { get; set; }
    public Func<string, Guid, string, Guid, RotationResult>? Rotate { get; set; }
    public List<(string OldDigest, Guid NewId, string NewDigest, Guid Correlation, DateTimeOffset At)> Rotations { get; } = [];
    public IEnumerable<T> All<T>() => Rows.OfType<T>();
    public T One<T>() => All<T>().Single();
    public void Seed(params object[] values) => Rows.AddRange(values);

    public async Task<T> ExecuteAsync<T>(Func<IAuthTransaction, Task<T>> action, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        BeforeExecute?.Invoke(Committed + 1);
        var working = Rows.Select(row => JsonSerializer.Deserialize(JsonSerializer.Serialize(row, row.GetType()), row.GetType())!).ToList();
        var value = await action(new Transaction(this, working));
        Rows = working;
        Committed++;
        return value;
    }

    private sealed class Transaction(MemoryAuthStore store, List<object> rows) : IAuthTransaction
    {
        private Task<T?> Find<T>(Func<T, bool> predicate) where T : class => Task.FromResult(rows.OfType<T>().SingleOrDefault(predicate));
        private Task<List<T>> List<T>(Func<T, bool> predicate) => Task.FromResult(rows.OfType<T>().Where(predicate).ToList());
        public Task LockAsync(string key, CancellationToken ct) { ct.ThrowIfCancellationRequested(); store.Locks.Add(key); return Task.CompletedTask; }
        public Task<Identity?> IdentityAsync(Guid id, CancellationToken ct) => Find<Identity>(x => x.IdentityId == id);
        public Task<Identity?> IdentityByEmailAsync(string email, CancellationToken ct) => Find<Identity>(x => x.LoginEmail == email);
        public Task<PasswordCredential?> CredentialAsync(Guid id, CancellationToken ct) => Find<PasswordCredential>(x => x.IdentityId == id);
        public Task<AuthSession?> SessionAsync(Guid id, CancellationToken ct) => Find<AuthSession>(x => x.SessionId == id);
        public Task<List<AuthSession>> SessionsAsync(Guid identity, CancellationToken ct) => List<AuthSession>(x => x.IdentityId == identity);
        public Task<List<RefreshToken>> FamilyAsync(Guid session, CancellationToken ct) => List<RefreshToken>(x => x.SessionId == session);
        public Task<AccountChallenge?> ChallengeAsync(string digest, CancellationToken ct) => Find<AccountChallenge>(x => x.SecretDigest == digest);
        public Task<List<AccountChallenge>> ChallengesAsync(Guid identity, string purpose, CancellationToken ct) => List<AccountChallenge>(x => x.IdentityId == identity && x.Purpose == purpose);
        public Task<List<ChallengeDelivery>> DeliveriesAsync(Guid challenge, CancellationToken ct) => List<ChallengeDelivery>(x => x.ChallengeId == challenge);
        public Task<OidcRequest?> OidcAsync(string digest, CancellationToken ct) => Find<OidcRequest>(x => x.StateDigest == digest);
        public Task<ExternalIdentity?> ExternalAsync(string issuer, string subject, CancellationToken ct) => Find<ExternalIdentity>(x => x.Issuer == issuer && x.Subject == subject);
        public Task<AuthOperation?> OperationAsync(Guid id, CancellationToken ct) => Find<AuthOperation>(x => x.OperationId == id);
        public Task<RotationResult> RotateAsync(string oldDigest, Guid newId, string newDigest, Guid correlation, DateTimeOffset at, CancellationToken ct)
        {
            store.Rotations.Add((oldDigest, newId, newDigest, correlation, at));
            return Task.FromResult(store.Rotate?.Invoke(oldDigest, newId, newDigest, correlation) ?? new RotationResult("Denied", null, null));
        }
        public void Add<T>(T entity) where T : class => rows.Add(entity);
    }
}
