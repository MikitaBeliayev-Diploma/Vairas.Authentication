using System.Security.Cryptography;
using System.Text;

namespace Vairas.Authentication.Business;
public sealed class VerifiedEmailService(IAuthStore store, TimeProvider clock) : IVerifiedEmailService
{
    public Task<VerifiedEmailResponse> ReadAsync(Guid identity, CancellationToken ct)
    {
        if (identity == Guid.Empty) throw AuthErrors.Invalid();
        return store.ExecuteAsync(async tx =>
        {
            var row = await tx.IdentityAsync(identity, ct);
            var eligible = row is { SecurityState: "Enabled", EmailVerifiedAt: not null, LoginEmail: not null } && row.EmailVerifiedAt <= clock.GetUtcNow();
            var revision = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"{identity:D}|{row?.LoginEmail}|{row?.EmailVerifiedAt:O}|{row?.SecurityState}")));
            return new VerifiedEmailResponse(identity, eligible, eligible ? row!.LoginEmail : null, revision, clock.GetUtcNow().AddSeconds(30));
        }, ct);
    }
}
