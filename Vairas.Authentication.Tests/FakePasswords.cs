using System.Text.Json;
using Vairas.Authentication.Business;
using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Tests;

internal sealed class FakePasswords : IPasswordHasher
{
    public int DummyCalls { get; private set; }
    public Action? DuringVerify { get; set; }
    public string Hash(string password) => "hash:" + password;
    public bool Verify(string hash, string password) { DuringVerify?.Invoke(); return hash == Hash(password); }
    public void DummyVerify(string password) => DummyCalls++;
}
