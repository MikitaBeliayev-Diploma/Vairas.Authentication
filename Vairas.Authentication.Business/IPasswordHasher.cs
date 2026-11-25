using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

public interface IPasswordHasher
{
    string Hash(string password);
    bool Verify(string hash, string password);
    void DummyVerify(string password);
}
