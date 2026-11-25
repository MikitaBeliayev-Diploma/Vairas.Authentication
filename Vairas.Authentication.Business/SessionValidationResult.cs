using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

/// <summary>Authoritative Authentication admission, not school authorization.</summary>
public sealed record SessionValidationResult(bool Active, Guid IdentityId, Guid SessionId, DateTimeOffset ValidUntil);
