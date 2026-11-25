using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

public interface ISecretProtector
{
    string Protect(string purpose, string value);
    string Unprotect(string purpose, string value);
}
