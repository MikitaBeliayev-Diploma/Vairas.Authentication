namespace Vairas.Authentication.Domain;

public sealed class Identity
{
    public Guid IdentityId { get; set; }
    public string? LoginEmail { get; set; }
    public DateTimeOffset? EmailVerifiedAt { get; set; }
    public string SecurityState { get; set; } = "Enabled";
    public long CredentialRevision { get; set; } = 1;
    public DateTimeOffset CreatedAt { get; set; }
}
