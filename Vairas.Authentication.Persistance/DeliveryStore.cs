using Microsoft.EntityFrameworkCore;
using Vairas.Authentication.Business;
using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Persistance;

public sealed class DeliveryStore(AuthDbContext db, TimeProvider clock) : IDeliveryStore
{
    public async Task<ChallengeDelivery?> ClaimAsync(CancellationToken ct)
    {
        db.ChangeTracker.Clear();
        var now = AuthPolicy.Now(clock);
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        // A worker may have died after DATA acceptance; an expired Sending lease is not proof of non-delivery.
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE challenge_delivery SET status='Unknown', protected_payload=NULL, last_error_code='LEASE_EXPIRED',lease_id=NULL,leased_until=NULL WHERE status='Sending' AND leased_until<={now}", ct);
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE challenge_delivery SET status='Expired', protected_payload=NULL WHERE status='Pending' AND expires_at<={now}", ct);
        var rows = await db.Set<ChallengeDelivery>().FromSqlInterpolated($"SELECT * FROM challenge_delivery WHERE status='Pending' AND next_attempt_at<={now} AND expires_at>{now} ORDER BY next_attempt_at,created_at LIMIT 1 FOR UPDATE SKIP LOCKED").ToListAsync(ct);
        var row = rows.SingleOrDefault();
        if (row is not null)
        {
            if (!await IsCurrentAsync(row.ChallengeId, ct)) { row.Status = "Superseded"; row.ProtectedPayload = null; }
            else { row.Status = "Sending"; row.Attempts++; row.LeaseId = Guid.NewGuid(); row.LeasedUntil = now.AddMinutes(2); }
            await db.SaveChangesAsync(ct);
        }
        await transaction.CommitAsync(ct);
        return row?.Status == "Sending" ? row : null;
    }
    public Task<bool> IsCurrentAsync(Guid id, CancellationToken ct)
    {
        var now = AuthPolicy.Now(clock);
        return (from c in db.Set<AccountChallenge>() join i in db.Set<Identity>() on c.IdentityId equals i.IdentityId
                where c.ChallengeId == id && c.ConsumedAt == null && c.InvalidatedAt == null && c.ExpiresAt > now &&
                    i.SecurityState == "Enabled" && i.CredentialRevision == c.CredentialRevision && i.LoginEmail == c.LoginEmail
                select c.ChallengeId).AnyAsync(ct);
    }
    public async Task CompleteAsync(Guid id, Guid lease, DeliveryResult result, CancellationToken ct)
    {
        db.ChangeTracker.Clear();
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var row = (await db.Set<ChallengeDelivery>().FromSqlInterpolated($"SELECT * FROM challenge_delivery WHERE delivery_id={id} FOR UPDATE").ToListAsync(ct)).SingleOrDefault();
        if (row is null || row.Status != "Sending" || row.LeaseId != lease) return;
        row.LastErrorCode = result.ErrorCode;
        row.LeaseId = null; row.LeasedUntil = null;
        if (result.Status == "Retry" && row.Attempts < 8 && row.ExpiresAt > clock.GetUtcNow())
        {
            row.Status = "Pending";
            row.NextAttemptAt = AuthPolicy.Now(clock).AddSeconds(Math.Min(300, Math.Pow(2, row.Attempts)));
        }
        else
        {
            row.Status = result.Status == "Retry" ? "Failed" : result.Status;
            row.ProtectedPayload = null;
        }
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);
    }
}
