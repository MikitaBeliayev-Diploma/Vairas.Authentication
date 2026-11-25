using Vairas.Authentication.Business;
using Vairas.Authentication.Integrations;
using Vairas.Authentication.Workers;

namespace Vairas.Authentication.Configuration;

/// <summary>Verification challenge delivery over SMTP and its background worker.</summary>
public static class ConfigureChallengeDelivery
{
    public static IServiceCollection AddChallengeDelivery(this IServiceCollection services)
    {
        services.AddSingleton<IChallengeSender, SmtpChallengeSender>();
        services.AddHostedService<ChallengeDeliveryWorker>();
        return services;
    }
}
