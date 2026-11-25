using System.Text.Json;
using Vairas.Authentication.Business;
using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Tests;

internal sealed class FakeTokens : IUserTokenIssuer
{
    public int LifetimeSeconds { get; set; } = 300;
    public bool Fail { get; set; }
    public List<(Guid Identity, Guid Session, DateTimeOffset Now, DateTimeOffset Expires)> Issued { get; } = [];
    public string Issue(Guid identity, Guid session, DateTimeOffset now, DateTimeOffset expiresAt)
    {
        if (Fail) throw AuthErrors.Dependency();
        Issued.Add((identity, session, now, expiresAt));
        return "fake-access-token";
    }
}
