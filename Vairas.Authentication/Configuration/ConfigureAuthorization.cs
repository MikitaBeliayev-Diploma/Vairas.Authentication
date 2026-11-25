using Microsoft.AspNetCore.Authorization;
using Vairas.Authentication.Security;

namespace Vairas.Authentication.Configuration;

public static class ConfigureAuthorization
{
    public static IServiceCollection AddWorkloadAuthorization(this IServiceCollection services)
    {
        services.AddAuthorization(options =>
        {
            options.AddPolicy("IdentityValidate", policy => policy.AddAuthenticationSchemes("Workload")
                .RequireAuthenticatedUser().AddRequirements(new WorkloadScope("identity.validate")));
            options.AddPolicy("IdentityContactRead", policy => policy.AddAuthenticationSchemes("Workload")
                .RequireAuthenticatedUser().AddRequirements(new WorkloadScope("identity.contact.read")));
        });
        services.AddSingleton<IAuthorizationHandler, WorkloadScopeHandler>();
        return services;
    }
}
