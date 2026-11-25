using System.Text.Json;
using Vairas.Authentication.Business;
using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Tests;

internal sealed class FakeOidc : IOidcProvider
{
    public ExternalSubject Subject { get; set; } = new("https://issuer.test", "external-subject");
    public Exception? ExchangeFailure { get; set; }
    public int Exchanges { get; private set; }
    public (string State, string Nonce, string Verifier)? Authorization { get; private set; }
    public OidcSecrets? ExchangedSecrets { get; private set; }
    public void Validate(string issuer, string redirectUri)
    {
        if (issuer != "https://issuer.test" || redirectUri != "https://client.test/callback") throw AuthErrors.Invalid();
    }
    public Task<string> AuthorizationUrlAsync(string issuer, string redirect, string state, string nonce, string verifier, CancellationToken ct)
    {
        Authorization = (state, nonce, verifier);
        return Task.FromResult("https://issuer.test/authorize?state=" + state);
    }
    public Task<ExternalSubject> ExchangeAsync(string issuer, string redirect, string code, OidcSecrets secrets, CancellationToken ct)
    {
        Exchanges++;
        ExchangedSecrets = secrets;
        return ExchangeFailure is null ? Task.FromResult(Subject) : Task.FromException<ExternalSubject>(ExchangeFailure);
    }
}
