using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration;
using Vairas.Authentication.Middleware;
using Vairas.Authentication.Security;
using IAuthenticationService = Vairas.Authentication.Business.IAuthenticationService;
using Vairas.Authentication.Configuration.Options;

namespace Vairas.Authentication.Controllers;

[Route("api/v1/auth"), EnableRateLimiting("public")]
[ProducesResponseType<ProblemDetails>(400), ProducesResponseType<ProblemDetails>(401), ProducesResponseType<ProblemDetails>(403)]
[ProducesResponseType<ProblemDetails>(409), ProducesResponseType<ProblemDetails>(429), ProducesResponseType<ProblemDetails>(503)]
public sealed class AuthenticationController(IAuthenticationService service, AuthOptions settings) : BaseApiController
{
    /// <summary>Register credentials and queue email verification without disclosing account existence.</summary>
    [HttpPost("registrations"), AllowAnonymous, ProducesResponseType<AcceptedResponse>(202)]
    public async Task<ActionResult<AcceptedResponse>> Register(CredentialsRequest request, CancellationToken ct) =>
        StatusCode(202, await service.RegisterAsync(request, CorrelationMiddleware.Audit(HttpContext), ct));

    /// <summary>Authenticate a verified local password and create a session.</summary>
    [HttpPost("login"), AllowAnonymous, ProducesResponseType<TokenPair>(200)]
    public Task<TokenPair> Login(CredentialsRequest request, CancellationToken ct) => service.LoginAsync(request, CorrelationMiddleware.Audit(HttpContext), ct);

    /// <summary>Rotate a refresh credential once; detected reuse revokes the session.</summary>
    [HttpPost("refresh"), AllowAnonymous, ProducesResponseType<TokenPair>(200)]
    public Task<TokenPair> Refresh(RefreshRequest request, CancellationToken ct) => service.RefreshAsync(request, CorrelationMiddleware.Audit(HttpContext), ct);

    /// <summary>Queue a purpose-bound email challenge, returning a generic acknowledgment.</summary>
    [HttpPost("challenges"), AllowAnonymous, ProducesResponseType<AcceptedResponse>(202)]
    public async Task<ActionResult<AcceptedResponse>> Challenge(ChallengeRequest request, CancellationToken ct) =>
        StatusCode(202, await service.ChallengeAsync(request, CorrelationMiddleware.Audit(HttpContext), ct));

    /// <summary>Consume a one-time challenge; password resets revoke all sessions.</summary>
    [HttpPost("challenges/completion"), AllowAnonymous, ProducesResponseType<AcceptedResponse>(200)]
    public Task<AcceptedResponse> Complete(ChallengeCompletionRequest request, CancellationToken ct) =>
        service.CompleteAsync(request, CorrelationMiddleware.Audit(HttpContext), ct);

    /// <summary>Begin a configured external OIDC login or an authenticated explicit link.</summary>
    [HttpPost("oidc/requests"), AllowAnonymous, ProducesResponseType<OidcRedirect>(200)]
    public async Task<OidcRedirect> BeginOidc(OidcStartRequest request, CancellationToken ct)
    {
        UserActor? actor = null;
        if (request.Purpose == "Link")
        {
            var user = await HttpContext.AuthenticateAsync("User");
            if (!user.Succeeded || user.Principal is null) throw AuthErrors.Denied();
            actor = ActorClaims.Actor(user.Principal);
        }
        var browser = AuthPolicy.RandomSecret();
        var result = await service.BeginOidcAsync(request, actor, browser, CorrelationMiddleware.Audit(HttpContext), ct);
        Response.Cookies.Append(AuthPolicy.CookieName(result.State), browser, new CookieOptions
        {
            Secure = true, HttpOnly = true, SameSite = Enum.Parse<SameSiteMode>(settings.OidcCookieSameSite), Path = "/", MaxAge = TimeSpan.FromMinutes(10), IsEssential = true
        });
        return new(result.AuthorizationUrl);
    }

    /// <summary>Complete the single-use browser-bound OIDC exchange.</summary>
    [HttpPost("oidc/callback"), AllowAnonymous, ProducesResponseType<TokenPair>(200)]
    public async Task<TokenPair> CompleteOidc(OidcCallbackRequest request, CancellationToken ct)
    {
        AuthPolicy.Secret(request.State);
        var name = AuthPolicy.CookieName(request.State);
        var browser = Request.Cookies[name];
        if (browser is null) throw AuthErrors.Denied();
        Response.Cookies.Delete(name, new CookieOptions { Secure = true, HttpOnly = true, SameSite = Enum.Parse<SameSiteMode>(settings.OidcCookieSameSite), Path = "/" });
        return await service.CompleteOidcAsync(request, browser, CorrelationMiddleware.Audit(HttpContext), ct);
    }

    /// <summary>Revoke an owned session using a stable idempotency key.</summary>
    [HttpPost("sessions/{sessionId:guid}/revocation"), Authorize(AuthenticationSchemes = "User"), ProducesResponseType<SessionRevocation>(200)]
    public Task<SessionRevocation> Revoke(Guid sessionId, [FromHeader(Name = "Idempotency-Key")] Guid operationId, CancellationToken ct) =>
        service.RevokeAsync(ActorClaims.Actor(User), sessionId, operationId, CorrelationMiddleware.Audit(HttpContext), ct);
}
