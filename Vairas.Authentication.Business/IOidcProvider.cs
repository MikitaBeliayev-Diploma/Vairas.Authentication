using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

public interface IOidcProvider
{
    void Validate(string issuer, string redirectUri);
    Task<string> AuthorizationUrlAsync(string issuer, string redirect, string state, string nonce, string verifier, CancellationToken ct);
    Task<ExternalSubject> ExchangeAsync(string issuer, string redirect, string code, OidcSecrets secrets, CancellationToken ct);
}
