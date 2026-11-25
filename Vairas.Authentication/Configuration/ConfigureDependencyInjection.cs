using Vairas.Authentication.Business;
using Vairas.Authentication.Integrations;
using Vairas.Authentication.Security;

namespace Vairas.Authentication.Configuration;

/// <summary>Application services; infrastructure registrations live in the dedicated Configure* classes.</summary>
public static class ConfigureDependencyInjection
{
    public static IServiceCollection AddAuthenticationServices(this IServiceCollection services)
    {
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<IPasswordHasher, PasswordHasher>();
        services.AddSingleton<IAccountThrottle, AccountThrottle>();
        services.AddSingleton<SigningKeys>();
        services.AddSingleton<TokenService>();
        services.AddScoped<TokenExchange>();
        services.AddSingleton<IUserTokenIssuer>(provider => provider.GetRequiredService<TokenService>());
        services.AddSingleton<IWorkloadTokenService>(provider => provider.GetRequiredService<TokenService>());
        services.AddSingleton<ISecretProtector, SecretProtector>();
        services.AddScoped<IAuthenticationService, AuthenticationService>();
        services.AddScoped<IVerifiedEmailService, VerifiedEmailService>();
        return services;
    }
}
