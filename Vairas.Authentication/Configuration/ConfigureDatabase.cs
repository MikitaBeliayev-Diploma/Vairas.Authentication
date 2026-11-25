using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration.Options;
using Vairas.Authentication.Persistance;

namespace Vairas.Authentication.Configuration;

public static class ConfigureDatabase
{
    public static IServiceCollection AddAuthenticationDatabase(this IServiceCollection services)
    {
        services.AddDbContext<AuthDbContext>((provider, builder) =>
            builder.UseNpgsql(provider.GetRequiredService<IOptions<DatabaseOptions>>().Value.Authentication));
        services.AddScoped<IAuthStore, AuthStore>();
        services.AddScoped<IDeliveryStore, DeliveryStore>();
        return services;
    }
}
