using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Vairas.Authentication.Configuration.Options;

namespace Vairas.Authentication.Configuration;

/// <summary>Protected key ring for stored secrets; the ring is encrypted with a certificate or, on Windows, DPAPI.</summary>
public static class ConfigureDataProtection
{
    public static IServiceCollection AddSecretProtection(this IServiceCollection services)
    {
    services.AddSingleton<IDataProtectionProvider>(p =>
    {
        var protection = p.GetRequiredService<ProtectionOptions>();
        return DataProtectionProvider.Create(new DirectoryInfo(protection.KeyRingPath), dataProtection =>
        {
            dataProtection.SetApplicationName("Vairas.Authentication");
            if (!string.IsNullOrEmpty(protection.CertificatePath))
                dataProtection.ProtectKeysWithCertificate(X509CertificateLoader.LoadPkcs12FromFile(protection.CertificatePath, protection.CertificatePassword, X509KeyStorageFlags.EphemeralKeySet));
            else if (OperatingSystem.IsWindows()) dataProtection.ProtectKeysWithDpapi();
            else throw new InvalidOperationException("Non-Windows hosts require an explicit key-ring encryption certificate.");
        });
    });
        return services;
    }
}
