namespace Vairas.Authentication.Configuration.Options;


public sealed class ProtectionOptions
{
    public string KeyRingPath { get; set; } = "";
    public string? CertificatePath { get; set; }
    public string? CertificatePassword { get; set; }
}
