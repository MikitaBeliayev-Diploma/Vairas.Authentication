namespace Vairas.Authentication.Domain;

public sealed class RefreshToken
{
    public Guid RefreshTokenId { get; set; }
    public Guid SessionId { get; set; }
    public Guid? ParentTokenId { get; set; }
    public string SecretDigest { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}
