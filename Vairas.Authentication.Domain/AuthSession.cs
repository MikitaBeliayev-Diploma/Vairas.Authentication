namespace Vairas.Authentication.Domain;

public sealed class AuthSession
{
    public Guid SessionId { get; set; }
    public Guid IdentityId { get; set; }
    public string AuthMethod { get; set; } = "Password";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? RevocationReason { get; set; }
}
