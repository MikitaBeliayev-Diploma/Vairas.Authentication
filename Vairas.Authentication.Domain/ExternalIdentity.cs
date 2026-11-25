namespace Vairas.Authentication.Domain;

public sealed class ExternalIdentity
{
    public Guid ExternalIdentityId { get; set; }
    public Guid IdentityId { get; set; }
    public string Issuer { get; set; } = "";
    public string Subject { get; set; } = "";
    public DateTimeOffset LinkedAt { get; set; }
}
