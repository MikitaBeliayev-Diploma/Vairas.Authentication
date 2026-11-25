using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

public sealed record OidcStartResult(string AuthorizationUrl, string State);
