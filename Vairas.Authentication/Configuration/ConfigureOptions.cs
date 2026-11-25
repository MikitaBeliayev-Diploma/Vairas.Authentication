using Microsoft.Extensions.Options;
using Vairas.Authentication.Configuration.Options;

namespace Vairas.Authentication.Configuration;

/// <summary>Binds and validates every strongly typed options section; invalid required settings fail at startup.</summary>
public static class ConfigureOptions
{
    public static IServiceCollection AddAuthenticationOptions(this IServiceCollection services, IConfiguration configuration)
    {
        AddValidated<DatabaseOptions, DatabaseOptionsValidator>(services, configuration.GetSection("ConnectionStrings"));
        AddValidated<AuthOptions, AuthOptionsValidator>(services, configuration.GetSection("Authentication"));
        AddValidated<SmtpOptions, SmtpOptionsValidator>(services, configuration.GetSection("Smtp"));
        AddValidated<ProtectionOptions, ProtectionOptionsValidator>(services, configuration.GetSection("Protection"));
        services.AddOptions<RateLimitOptions>().Bind(configuration.GetSection("RateLimits"));
        // Token, OIDC and delivery components take the plain settings objects so their constructors stay independent of the options infrastructure.
        services.AddSingleton(provider => provider.GetRequiredService<IOptions<AuthOptions>>().Value);
        services.AddSingleton(provider => provider.GetRequiredService<IOptions<SmtpOptions>>().Value);
        services.AddSingleton(provider => provider.GetRequiredService<IOptions<ProtectionOptions>>().Value);
        return services;
    }

    private static void AddValidated<TOptions, TValidator>(IServiceCollection services, IConfigurationSection section)
        where TOptions : class
        where TValidator : class, IValidateOptions<TOptions>
    {
        services.AddOptions<TOptions>().Bind(section).ValidateOnStart();
        services.AddSingleton<IValidateOptions<TOptions>, TValidator>();
    }
}
