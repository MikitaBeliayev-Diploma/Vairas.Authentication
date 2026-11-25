using System.Text.Json;
using Vairas.Authentication.Business;
using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Tests;

internal sealed class FakeThrottle : IAccountThrottle
{
    public List<(string Email, string Operation)> Checks { get; } = [];
    public bool Reject { get; set; }
    public void Check(string normalizedEmail, string operation)
    {
        Checks.Add((normalizedEmail, operation));
        if (Reject) throw new TooManyRequestsException("RATE_LIMITED", "Try later.");
    }
}
