using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

/// <summary>A request authenticated by a one-use opaque refresh credential.</summary>
public sealed record RefreshRequest(string RefreshToken);
