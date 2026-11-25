using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

/// <summary>Start a configured external login or explicit account link.</summary>
public sealed record OidcStartRequest(string Issuer, string RedirectUri, string Purpose);
