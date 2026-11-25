using Microsoft.AspNetCore.Cors.Infrastructure;
using Vairas.Authentication.Configuration.Options;

namespace Vairas.Authentication.Configuration;

public static class ConfigureCors
{
    public static IServiceCollection AddBrowserCors(this IServiceCollection services)
    {
        services.AddCors();
        services.AddOptions<CorsOptions>().Configure<AuthOptions>((cors, settings) =>
            cors.AddDefaultPolicy(policy =>
            {
                if (settings.BrowserOrigins.Length > 0)
                    policy.WithOrigins(settings.BrowserOrigins).AllowAnyHeader().AllowAnyMethod().AllowCredentials();
            }));
        return services;
    }
}
