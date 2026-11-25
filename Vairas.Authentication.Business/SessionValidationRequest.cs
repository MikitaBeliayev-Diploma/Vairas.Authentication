using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

/// <summary>Exact identity/session pair to validate.</summary>
public sealed record SessionValidationRequest(Guid IdentityId, Guid SessionId);
