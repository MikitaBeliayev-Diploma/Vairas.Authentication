using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Persistance;

public sealed class AuthDbContext(DbContextOptions<AuthDbContext> options) : DbContext(options)
{
    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<Identity>().ToTable("identity").HasKey(x => x.IdentityId);
        b.Entity<PasswordCredential>().ToTable("password_credential").HasKey(x => x.IdentityId);
        b.Entity<ExternalIdentity>().ToTable("external_identity").HasKey(x => x.ExternalIdentityId);
        b.Entity<AuthSession>().ToTable("auth_session").HasKey(x => x.SessionId);
        b.Entity<RefreshToken>().ToTable("refresh_token").HasKey(x => x.RefreshTokenId);
        b.Entity<AccountChallenge>().ToTable("account_challenge").HasKey(x => x.ChallengeId);
        b.Entity<OidcRequest>().ToTable("oidc_request").HasKey(x => x.RequestId);
        b.Entity<SecurityEvent>().ToTable("security_event").HasKey(x => x.EventId);
        b.Entity<AuthOperation>().ToTable("auth_operation").HasKey(x => x.OperationId);
        b.Entity<ChallengeDelivery>().ToTable("challenge_delivery").HasKey(x => x.DeliveryId);

        b.Entity<Identity>().Property(x => x.LoginEmail).HasMaxLength(254);
        b.Entity<Identity>().Property(x => x.SecurityState).HasMaxLength(16).HasDefaultValue("Enabled");
        b.Entity<Identity>().Property(x => x.CredentialRevision).HasDefaultValue(1L);
        b.Entity<Identity>().HasIndex(x => x.LoginEmail).IsUnique();
        b.Entity<PasswordCredential>().HasOne<Identity>().WithMany().HasForeignKey(x => x.IdentityId).OnDelete(DeleteBehavior.NoAction);
        b.Entity<ExternalIdentity>().Property(x => x.Issuer).HasMaxLength(512);
        b.Entity<ExternalIdentity>().Property(x => x.Subject).HasMaxLength(255);
        b.Entity<ExternalIdentity>().HasIndex(x => new { x.Issuer, x.Subject }).IsUnique();
        b.Entity<ExternalIdentity>().HasOne<Identity>().WithMany().HasForeignKey(x => x.IdentityId).OnDelete(DeleteBehavior.NoAction);
        b.Entity<AuthSession>().Property(x => x.AuthMethod).HasMaxLength(16);
        b.Entity<AuthSession>().Property(x => x.RevocationReason).HasMaxLength(40);
        b.Entity<AuthSession>().HasAlternateKey(x => new { x.SessionId, x.IdentityId });
        b.Entity<AuthSession>().HasOne<Identity>().WithMany().HasForeignKey(x => x.IdentityId).OnDelete(DeleteBehavior.NoAction);
        b.Entity<RefreshToken>().Property(x => x.SecretDigest).HasMaxLength(64);
        b.Entity<RefreshToken>().HasAlternateKey(x => new { x.RefreshTokenId, x.SessionId });
        b.Entity<RefreshToken>().HasOne<AuthSession>().WithMany().HasForeignKey(x => x.SessionId).OnDelete(DeleteBehavior.NoAction);
        b.Entity<RefreshToken>().HasOne<RefreshToken>().WithMany().HasForeignKey(x => new { x.ParentTokenId, x.SessionId })
            .HasPrincipalKey(x => new { x.RefreshTokenId, x.SessionId }).OnDelete(DeleteBehavior.NoAction);
        b.Entity<RefreshToken>().HasIndex(x => x.SecretDigest).IsUnique();
        b.Entity<RefreshToken>().HasIndex(x => new { x.ParentTokenId, x.SessionId }).IsUnique();
        b.Entity<RefreshToken>().HasIndex(x => x.SessionId, "ux_refresh_live").IsUnique().HasFilter("consumed_at IS NULL AND revoked_at IS NULL");
        b.Entity<RefreshToken>().HasIndex(x => x.SessionId, "ux_refresh_root").IsUnique().HasFilter("parent_token_id IS NULL");
        b.Entity<AccountChallenge>().Property(x => x.Purpose).HasMaxLength(20);
        b.Entity<AccountChallenge>().Property(x => x.LoginEmail).HasMaxLength(254);
        b.Entity<AccountChallenge>().Property(x => x.SecretDigest).HasMaxLength(64);
        b.Entity<AccountChallenge>().HasOne<Identity>().WithMany().HasForeignKey(x => x.IdentityId).OnDelete(DeleteBehavior.NoAction);
        b.Entity<AccountChallenge>().HasIndex(x => x.SecretDigest).IsUnique();
        b.Entity<AccountChallenge>().HasIndex(x => new { x.IdentityId, x.Purpose }).IsUnique().HasDatabaseName("ux_challenge_live")
            .HasFilter("consumed_at IS NULL AND invalidated_at IS NULL");
        b.Entity<OidcRequest>().Property(x => x.Purpose).HasMaxLength(8);
        b.Entity<OidcRequest>().Property(x => x.Issuer).HasMaxLength(512);
        b.Entity<OidcRequest>().Property(x => x.StateDigest).HasMaxLength(64);
        b.Entity<OidcRequest>().Property(x => x.BrowserDigest).HasMaxLength(64);
        b.Entity<OidcRequest>().Property(x => x.NonceDigest).HasMaxLength(64);
        b.Entity<OidcRequest>().Property(x => x.RedirectUri).HasMaxLength(1024);
        b.Entity<OidcRequest>().HasIndex(x => x.StateDigest).IsUnique();
        b.Entity<OidcRequest>().HasOne<AuthSession>().WithMany().HasForeignKey(x => new { x.LinkSessionId, x.LinkIdentityId })
            .HasPrincipalKey(x => new { x.SessionId, x.IdentityId }).OnDelete(DeleteBehavior.NoAction);
        b.Entity<SecurityEvent>().Property(x => x.EventType).HasMaxLength(48);
        b.Entity<SecurityEvent>().Property(x => x.OutcomeCode).HasMaxLength(48);
        b.Entity<SecurityEvent>().HasOne<Identity>().WithMany().HasForeignKey(x => x.IdentityId).OnDelete(DeleteBehavior.NoAction);
        b.Entity<SecurityEvent>().HasOne<AuthSession>().WithMany().HasForeignKey(x => new { x.SessionId, x.IdentityId })
            .HasPrincipalKey(x => new { x.SessionId, x.IdentityId }).OnDelete(DeleteBehavior.NoAction);
        b.Entity<SecurityEvent>().HasIndex(x => new { x.IdentityId, x.OccurredAt });
        b.Entity<AuthOperation>().Property(x => x.Fingerprint).HasMaxLength(64);
        b.Entity<AuthOperation>().HasOne<AuthSession>().WithMany().HasForeignKey(x => new { x.SourceSessionId, x.IdentityId })
            .HasPrincipalKey(x => new { x.SessionId, x.IdentityId }).OnDelete(DeleteBehavior.NoAction);
        b.Entity<ChallengeDelivery>().Property(x => x.Status).HasMaxLength(16);
        b.Entity<ChallengeDelivery>().Property(x => x.LastErrorCode).HasMaxLength(80);
        b.Entity<ChallengeDelivery>().HasOne<AccountChallenge>().WithMany().HasForeignKey(x => x.ChallengeId).OnDelete(DeleteBehavior.NoAction);
        b.Entity<ChallengeDelivery>().HasIndex(x => x.ChallengeId).IsUnique();
        b.Entity<ChallengeDelivery>().HasIndex(x => x.NextAttemptAt).HasFilter("status = 'Pending'");

        foreach (var entity in b.Model.GetEntityTypes())
        foreach (var property in entity.GetProperties())
        {
            property.SetColumnName(Regex.Replace(property.Name, "([a-z0-9])([A-Z])", "$1_$2").ToLowerInvariant());
            if (property.Name == "CreatedAt" && entity.ClrType != typeof(ChallengeDelivery)) property.SetDefaultValueSql("clock_timestamp()");
            if (property.Name is "ChangedAt" or "LinkedAt" or "OccurredAt") property.SetDefaultValueSql("clock_timestamp()");
        }
    }
}
