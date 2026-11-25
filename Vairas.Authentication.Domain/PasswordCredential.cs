namespace Vairas.Authentication.Domain;

public sealed class PasswordCredential
{
    public Guid IdentityId { get; set; }
    public string PasswordHash { get; set; } = "";
    public DateTimeOffset ChangedAt { get; set; }
}
