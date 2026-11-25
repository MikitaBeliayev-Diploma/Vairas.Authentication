using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration;
using Vairas.Authentication.Middleware;

namespace Vairas.Authentication.Security;


public sealed class WorkloadScopeHandler(IWorkloadTokenService tokens) : AuthorizationHandler<WorkloadScope>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, WorkloadScope requirement)
    {
        if (tokens.Allowed(context.User, requirement.Scope)) context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
