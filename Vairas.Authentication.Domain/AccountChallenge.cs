namespace Vairas.Authentication.Domain;

public sealed class AccountChallenge
{
    public Guid ChallengeId { get; set; }
    public Guid IdentityId { get; set; }
    public string Purpose { get; set; } = "";
    public string LoginEmail { get; set; } = "";
    public long CredentialRevision { get; set; }
    public string SecretDigest { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
    public DateTimeOffset? InvalidatedAt { get; set; }
}
