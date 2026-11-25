namespace Vairas.Authentication.Domain;

public sealed class OidcRequest
{
    public Guid RequestId { get; set; }
    public string Purpose { get; set; } = "";
    public string Issuer { get; set; } = "";
    public string StateDigest { get; set; } = "";
    public string BrowserDigest { get; set; } = "";
    public string NonceDigest { get; set; } = "";
    public string PkceVerifierCiphertext { get; set; } = "";
    public string RedirectUri { get; set; } = "";
    public Guid? LinkIdentityId { get; set; }
    public Guid? LinkSessionId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
}
