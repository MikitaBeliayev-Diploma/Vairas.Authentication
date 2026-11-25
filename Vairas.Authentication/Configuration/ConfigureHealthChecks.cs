using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Vairas.Authentication.HealthChecks;

namespace Vairas.Authentication.Configuration;

public static class ConfigureHealthChecks
{
    public static IServiceCollection AddServiceHealthChecks(this IServiceCollection services)
    {
        services.AddHealthChecks().AddCheck<DatabaseReadiness>("authentication", tags: ["ready"]);
        return services;
    }

    public static WebApplication MapServiceHealthChecks(this WebApplication app)
    {
        app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false });
        app.MapHealthChecks("/health/ready", new HealthCheckOptions { Predicate = registration => registration.Tags.Contains("ready") });
        return app;
    }
}
