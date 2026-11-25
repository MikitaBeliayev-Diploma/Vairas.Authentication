using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration;
using Vairas.Authentication.Security;
using Vairas.Authentication.Configuration.Options;

namespace Vairas.Authentication.Controllers;

/// <summary>OAuth2 client-credentials request. User password grants are not supported.</summary>
public sealed record WorkloadTokenRequest
{
    [FromForm(Name = "subject_token")] public string SubjectToken { get; init; } = "";
    [FromForm(Name = "subject_token_type")] public string SubjectTokenType { get; init; } = "";
    [FromForm(Name = "requested_token_type")] public string? RequestedTokenType { get; init; }
    [FromForm(Name = "resource")] public string Resource { get; init; } = "";
    [FromForm(Name = "lesson_action")] public string? LessonAction { get; init; }
    [FromForm(Name = "school_id")] public string SchoolId { get; init; } = "";
    [Required, FromForm(Name = "grant_type")] public string GrantType { get; init; } = "";
    [Required, FromForm(Name = "client_id")] public string ClientId { get; init; } = "";
    [Required, FromForm(Name = "client_secret")] public string ClientSecret { get; init; } = "";
    [Required, FromForm(Name = "scope")] public string Scope { get; init; } = "";
}
