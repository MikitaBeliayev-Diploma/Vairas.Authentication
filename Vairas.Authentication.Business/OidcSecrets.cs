using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

public sealed record OidcSecrets(string Verifier, string Nonce);
