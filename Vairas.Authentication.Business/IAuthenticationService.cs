using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

public interface IAuthenticationService
{
    Task<AcceptedResponse> RegisterAsync(CredentialsRequest request, AuditContext audit, CancellationToken ct);
    Task<TokenPair> LoginAsync(CredentialsRequest request, AuditContext audit, CancellationToken ct);
    Task<TokenPair> RefreshAsync(RefreshRequest request, AuditContext audit, CancellationToken ct);
    Task<AcceptedResponse> ChallengeAsync(ChallengeRequest request, AuditContext audit, CancellationToken ct);
    Task<AcceptedResponse> CompleteAsync(ChallengeCompletionRequest request, AuditContext audit, CancellationToken ct);
    Task<SessionValidationResult> ValidateAsync(SessionValidationRequest request, CancellationToken ct);
    Task<SessionRevocation> RevokeAsync(UserActor actor, Guid session, Guid operation, AuditContext audit, CancellationToken ct);
    Task<OidcStartResult> BeginOidcAsync(OidcStartRequest request, UserActor? actor, string browserSecret, AuditContext audit, CancellationToken ct);
    Task<TokenPair> CompleteOidcAsync(OidcCallbackRequest request, string browserSecret, AuditContext audit, CancellationToken ct);
}
