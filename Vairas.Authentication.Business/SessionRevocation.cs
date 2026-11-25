using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

/// <summary>The session affected by a completed revocation.</summary>
public sealed record SessionRevocation(Guid SessionId);
