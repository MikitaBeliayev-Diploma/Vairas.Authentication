using System.Threading.RateLimiting;
using Microsoft.Extensions.Options;
using Vairas.Authentication.Configuration.Options;
using Vairas.Authentication.Middleware;

namespace Vairas.Authentication.Configuration;

public static class ConfigureRateLimiting
{
    public static IServiceCollection AddPerAddressRateLimiting(this IServiceCollection services)
    {
        services.AddRateLimiter(options =>
        {
            foreach (var policy in new[] { "public", "token" })
                options.AddPolicy(policy, http =>
                {
                    var configured = http.RequestServices.GetRequiredService<IOptions<RateLimitOptions>>().Value.RequestsPerMinute;
                    return RateLimitPartition.GetFixedWindowLimiter(http.Connection.RemoteIpAddress?.ToString() ?? "unknown", _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = configured ?? (policy == "public" ? 30 : 60), Window = TimeSpan.FromMinutes(1), QueueLimit = 0
                    });
                });
            options.OnRejected = async (context, _) =>
            {
                context.HttpContext.Response.Headers.RetryAfter = "60";
                await ProblemResponses.WriteAsync(context.HttpContext, 429, "RATE_LIMITED", "Try again later.");
            };
        });
        return services;
    }
}
