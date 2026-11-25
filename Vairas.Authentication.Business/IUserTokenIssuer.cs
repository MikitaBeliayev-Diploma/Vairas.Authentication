using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

public interface IUserTokenIssuer
{
    int LifetimeSeconds { get; }
    string Issue(Guid identity, Guid session, DateTimeOffset now, DateTimeOffset expiresAt);
}
