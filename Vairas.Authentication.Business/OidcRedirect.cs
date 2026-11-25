using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

/// <summary>An external authorization URL; the browser must retain the correlation cookie.</summary>
public sealed record OidcRedirect(string AuthorizationUrl);
