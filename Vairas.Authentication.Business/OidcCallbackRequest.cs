using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

/// <summary>Complete a browser-correlated OIDC authorization-code transaction.</summary>
public sealed record OidcCallbackRequest(string Code, string State);
