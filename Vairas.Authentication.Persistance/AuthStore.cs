using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Vairas.Authentication.Business;
using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Persistance;

public sealed class AuthStore(AuthDbContext db) : IAuthStore, IAuthTransaction
{
    public Task<T> ExecuteAsync<T>(Func<IAuthTransaction, Task<T>> action, CancellationToken ct) => DatabaseExceptionTranslator.GuardAsync(() => ExecuteCoreAsync(action, ct));
    private async Task<T> ExecuteCoreAsync<T>(Func<IAuthTransaction, Task<T>> action, CancellationToken ct)
    {
        db.ChangeTracker.Clear();
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var result = await action(this);
        // Replacements must invalidate the old live challenge before inserting its successor (partial unique index).
        var added = db.ChangeTracker.Entries().Where(x => x.State == EntityState.Added).Select(x => x.Entity).ToArray();
        foreach (var item in added) db.Entry(item).State = EntityState.Detached;
        await db.SaveChangesAsync(ct);
        foreach (var item in added) db.Add(item);
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);
        db.ChangeTracker.Clear();
        return result;
    }

    public async Task LockAsync(string key, CancellationToken ct)
    {
        var hash = BinaryPrimitives.ReadInt64LittleEndian(SHA256.HashData(Encoding.UTF8.GetBytes(key)));
        await db.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_advisory_xact_lock({hash})", ct);
        // The canonical refresh function locks identity rows. Share that lock with reset/login/link/revocation.
        if (key.StartsWith("identity:", StringComparison.Ordinal) && Guid.TryParse(key[9..], out var identity))
            await db.Database.ExecuteSqlInterpolatedAsync($"SELECT identity_id FROM identity WHERE identity_id={identity} FOR UPDATE", ct);
        foreach (var entry in db.ChangeTracker.Entries().Where(x => x.State == EntityState.Unchanged).ToArray())
            await entry.ReloadAsync(ct);
    }
    public Task<Identity?> IdentityAsync(Guid id, CancellationToken ct) => db.Set<Identity>().SingleOrDefaultAsync(x => x.IdentityId == id, ct);
    public Task<Identity?> IdentityByEmailAsync(string email, CancellationToken ct) => db.Set<Identity>().SingleOrDefaultAsync(x => x.LoginEmail == email, ct);
    public Task<PasswordCredential?> CredentialAsync(Guid id, CancellationToken ct) => db.Set<PasswordCredential>().SingleOrDefaultAsync(x => x.IdentityId == id, ct);
    public Task<AuthSession?> SessionAsync(Guid id, CancellationToken ct) => db.Set<AuthSession>().SingleOrDefaultAsync(x => x.SessionId == id, ct);
    public Task<List<AuthSession>> SessionsAsync(Guid identity, CancellationToken ct) => db.Set<AuthSession>().Where(x => x.IdentityId == identity).ToListAsync(ct);
    public Task<List<RefreshToken>> FamilyAsync(Guid session, CancellationToken ct) => db.Set<RefreshToken>().Where(x => x.SessionId == session).ToListAsync(ct);
    public Task<AccountChallenge?> ChallengeAsync(string digest, CancellationToken ct) => db.Set<AccountChallenge>().SingleOrDefaultAsync(x => x.SecretDigest == digest, ct);
    public Task<List<AccountChallenge>> ChallengesAsync(Guid identity, string purpose, CancellationToken ct) => db.Set<AccountChallenge>().Where(x => x.IdentityId == identity && x.Purpose == purpose && x.ConsumedAt == null && x.InvalidatedAt == null).ToListAsync(ct);
    public Task<List<ChallengeDelivery>> DeliveriesAsync(Guid challenge, CancellationToken ct) => db.Set<ChallengeDelivery>().Where(x => x.ChallengeId == challenge).ToListAsync(ct);
    public Task<OidcRequest?> OidcAsync(string digest, CancellationToken ct) => db.Set<OidcRequest>().SingleOrDefaultAsync(x => x.StateDigest == digest, ct);
    public Task<ExternalIdentity?> ExternalAsync(string issuer, string subject, CancellationToken ct) => db.Set<ExternalIdentity>().SingleOrDefaultAsync(x => x.Issuer == issuer && x.Subject == subject, ct);
    public Task<AuthOperation?> OperationAsync(Guid id, CancellationToken ct) => db.Set<AuthOperation>().SingleOrDefaultAsync(x => x.OperationId == id, ct);
    public void Add<T>(T entity) where T : class => db.Add(entity);
    public async Task<RotationResult> RotateAsync(string oldDigest, Guid newId, string newDigest, Guid correlation, DateTimeOffset at, CancellationToken ct)
    {
        var values = await db.Database.SqlQueryRaw<RotationRow>(
            "SELECT outcome AS \"Outcome\", identity_id AS \"IdentityId\", session_id AS \"SessionId\" FROM auth_rotate_refresh(@old,@id,@digest,@correlation,@at)",
            new NpgsqlParameter("old", oldDigest), new NpgsqlParameter("id", newId), new NpgsqlParameter("digest", newDigest), new NpgsqlParameter("correlation", correlation),
            new NpgsqlParameter("at", NpgsqlTypes.NpgsqlDbType.TimestampTz) { Value = at.ToUniversalTime() })
            .ToListAsync(ct);
        var row = values.Single();
        return new(row.Outcome, row.IdentityId, row.SessionId);
    }
    private sealed class RotationRow
    {
        public string Outcome { get; set; } = "";
        public Guid? IdentityId { get; set; }
        public Guid? SessionId { get; set; }
    }
}
