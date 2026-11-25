using System.Text.Json;
using Vairas.Authentication.Business;
using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Tests;

internal sealed class FakeProtection : ISecretProtector
{
    public string Protect(string purpose, string value) => purpose + ":" + value;
    public string Unprotect(string purpose, string value) => value.StartsWith(purpose + ":", StringComparison.Ordinal)
        ? value[(purpose.Length + 1)..] : throw new InvalidOperationException("Wrong protection purpose.");
}
