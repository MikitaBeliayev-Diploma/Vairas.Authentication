using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

/// <summary>User access and single-use refresh credentials.</summary>
public sealed record TokenPair(string AccessToken, string RefreshToken, string TokenType, int ExpiresIn, Guid IdentityId, Guid SessionId);
