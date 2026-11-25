using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

public sealed record RotationResult(string Outcome, Guid? IdentityId, Guid? SessionId);
