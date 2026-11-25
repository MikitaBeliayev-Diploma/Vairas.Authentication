using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

public sealed record UserActor(Guid IdentityId, Guid SessionId);
