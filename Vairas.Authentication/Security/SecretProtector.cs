using System.Security.Cryptography;
using Isopoh.Cryptography.Argon2;
using Microsoft.AspNetCore.DataProtection;
using Vairas.Authentication.Business;

namespace Vairas.Authentication.Security;


public sealed class SecretProtector(IDataProtectionProvider provider) : ISecretProtector
{
    public string Protect(string purpose, string value) => provider.CreateProtector("Vairas.Authentication", purpose, "v1").Protect(value);
    public string Unprotect(string purpose, string value)
    {
        try { return provider.CreateProtector("Vairas.Authentication", purpose, "v1").Unprotect(value); }
        catch (CryptographicException) { throw AuthErrors.Dependency(); }
    }
}
