using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration;
using Vairas.Authentication.Security;
using Vairas.Authentication.Configuration.Options;

namespace Vairas.Authentication.Controllers;
public sealed class IdentityController(IAuthenticationService service, IWorkloadTokenService tokens, SigningKeys keys, AuthOptions options, TokenExchange exchange) : BaseApiController
{
    /// <summary>Obtain a scoped workload token for an allowlisted service client.</summary>
    [HttpPost("connect/token"), AllowAnonymous, EnableRateLimiting("token"), Consumes("application/x-www-form-urlencoded")]
    [RequestSizeLimit(24576)]
    [ProducesResponseType<WorkloadTokenResponse>(200), ProducesResponseType<ProblemDetails>(400), ProducesResponseType<ProblemDetails>(401)]
    public async Task<WorkloadTokenResponse> Token([FromForm] WorkloadTokenRequest request, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Response.Headers.CacheControl = "no-store"; Response.Headers.Pragma = "no-cache";
        if (request.GrantType == Vairas.Delegation.ReadPreviewDelegation.Grant)
        {
            HttpContext.Items["Vairas.TokenExchange"] = true;
            var form = await Request.ReadFormAsync(ct);
            string[] allowed = ["grant_type", "client_id", "client_secret", "subject_token", "subject_token_type", "requested_token_type", "resource", "scope", "school_id", "lesson_action"];
            if (form.Any(p => !allowed.Contains(p.Key, StringComparer.Ordinal) || p.Value.Count != 1)) throw AuthErrors.Invalid();
            var result = await exchange.IssueAsync(request.ClientId, request.ClientSecret, request.SubjectToken, request.SubjectTokenType, request.RequestedTokenType, request.Resource, request.Scope, request.SchoolId, ct, request.LessonAction);
            return new(result.AccessToken, result.TokenType, result.ExpiresIn, result.Scope, result.IssuedTokenType);
        }
        return tokens.Issue(request.GrantType, request.ClientId, request.ClientSecret, request.Scope);
    }
    /// <summary>Validate current Authentication admission for an exact identity/session pair.</summary>
    [HttpPost("internal/v1/sessions/validate"), Authorize(Policy = "IdentityValidate")]
    [ProducesResponseType<SessionValidationResult>(200), ProducesResponseType<ProblemDetails>(401), ProducesResponseType<ProblemDetails>(403), ProducesResponseType<ProblemDetails>(503)]
    public Task<SessionValidationResult> Validate(SessionValidationRequest request, CancellationToken ct) => service.ValidateAsync(request, ct);

    /// <summary>Return the issuer metadata required by JWT resource servers.</summary>
    [HttpGet(".well-known/openid-configuration"), AllowAnonymous, ProducesResponseType(200)]
    public object Discovery(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return new { issuer = options.Issuer, jwks_uri = options.Issuer.TrimEnd('/') + "/.well-known/jwks.json",
            token_endpoint = options.Issuer.TrimEnd('/') + "/connect/token", grant_types_supported = options.Delegation.Enabled ? new[] { "client_credentials", Vairas.Delegation.ReadPreviewDelegation.Grant } : new[] { "client_credentials" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_post" } };
    }
    /// <summary>Return current and previous public RSA signing keys.</summary>
    [HttpGet(".well-known/jwks.json"), AllowAnonymous, ProducesResponseType(200)]
    public object Jwks(CancellationToken ct) { ct.ThrowIfCancellationRequested(); Response.Headers.CacheControl = "public,max-age=60"; return keys.PublicJwks(); }
}
