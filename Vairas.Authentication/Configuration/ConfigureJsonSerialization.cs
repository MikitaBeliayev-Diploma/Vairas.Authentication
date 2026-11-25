using System.Text.Json.Serialization;

namespace Vairas.Authentication.Configuration;

public static class ConfigureJsonSerialization
{
    public static IServiceCollection AddJsonSerialization(this IServiceCollection services)
    {
        services.AddControllers().AddJsonOptions(options =>
        {
            var json = options.JsonSerializerOptions;
            json.PropertyNameCaseInsensitive = false;
            json.UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow;
            json.AllowDuplicateProperties = false;
            json.Converters.Add(new JsonStringEnumConverter());
        });
        return services;
    }
}
