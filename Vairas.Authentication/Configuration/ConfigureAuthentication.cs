using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Vairas.Authentication.Middleware;
using Vairas.Authentication.Configuration.Options;
using Vairas.Authentication.Security;

namespace Vairas.Authentication.Configuration;

/// <summary>Bearer validation for user tokens and internal workload tokens issued by this service.</summary>
public static class ConfigureAuthentication
{
    public static IServiceCollection AddBearerAuthentication(this IServiceCollection services)
    {
        services.AddAuthentication("User").AddJwtBearer("User", _ => { }).AddJwtBearer("Workload", _ => { });
        foreach (var scheme in new[] { "User", "Workload" })
        {
            var user = scheme == "User";
            services.AddOptions<JwtBearerOptions>(scheme).Configure<SigningKeys, AuthOptions>((options, keys, settings) =>
            {
                options.MapInboundClaims = false;
                options.IncludeErrorDetails = false;
                options.TokenValidationParameters = new()
                {
                    ValidateIssuer = true, ValidIssuer = settings.Issuer, ValidateAudience = true,
                    ValidAudience = user ? settings.UserAudience : settings.WorkloadAudience, ValidateLifetime = true,
                    RequireExpirationTime = true, ValidateIssuerSigningKey = true, IssuerSigningKeys = keys.ValidationKeys,
                    RequireSignedTokens = true, ValidAlgorithms = [SecurityAlgorithms.RsaSha256], ClockSkew = TimeSpan.FromSeconds(30), NameClaimType = "sub"
                };
                options.Events = new()
                {
                    OnTokenValidated = context =>
                    {
                        if (user && (!Guid.TryParse(context.Principal!.FindFirstValue("sub"), out var id) || id == Guid.Empty ||
                            !Guid.TryParse(context.Principal!.FindFirstValue("sid"), out var sid) || sid == Guid.Empty)) context.Fail("Invalid user binding.");
                        return Task.CompletedTask;
                    },
                    OnChallenge = context =>
                    {
                        context.HandleResponse(); context.Response.Headers.WWWAuthenticate = "Bearer";
                        return ProblemResponses.WriteAsync(context.HttpContext, 401, "AUTHENTICATION_REQUIRED", "Authentication required.");
                    },
                    OnForbidden = context => ProblemResponses.WriteAsync(context.HttpContext, 403, "ACCESS_DENIED", "Access denied.")
                };
            });
        }
        return services;
    }
}
