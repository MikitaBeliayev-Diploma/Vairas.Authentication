using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Vairas.Authentication.Business;

namespace Vairas.Authentication.Controllers;

[Route("internal/v1/identities/{identityId:guid}/verified-email"), Authorize(Policy = "IdentityContactRead")]
public sealed class VerifiedEmailController(IVerifiedEmailService service) : BaseApiController
{
    /// <summary>Read a short-lived verified-login-email decision for an authorized Notifications workload.</summary>
    [HttpGet(Name = "getVerifiedNotificationEmail")]
    public Task<VerifiedEmailResponse> Read(Guid identityId, CancellationToken ct) => service.ReadAsync(identityId, ct);
}
