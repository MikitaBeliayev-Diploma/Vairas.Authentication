using Vairas.Authentication.Business;
using Vairas.Authentication.Integrations;

namespace Vairas.Authentication.Configuration;

public static class ConfigureHttpClients
{
    public static IServiceCollection AddIdentityProviderHttpClients(this IServiceCollection services)
    {
        services.AddSingleton<IOidcProvider, OidcProvider>();
        services.AddHttpClient("oidc", client => client.Timeout = TimeSpan.FromSeconds(10))
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
        return services;
    }
}
