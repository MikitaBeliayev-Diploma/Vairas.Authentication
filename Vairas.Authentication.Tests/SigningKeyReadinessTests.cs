using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Moq;
using NUnit.Framework;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration;
using Vairas.Authentication.Security;
using Vairas.Authentication.Configuration.Options;

namespace Vairas.Authentication.Tests;

[TestFixture, Category("Integration")]
public sealed class SigningKeyReadinessTests
{
    [Test]
    public async Task RunningApplicationReadinessTracksSigningWindowAndRemainingTokenLifetime()
    {
        await using var environment = new TestEnvironment();
        await environment.StartAsync();
        var initial = DateTimeOffset.UtcNow;
        var clock = new SigningTestClock(initial);
        await using var factory = environment.Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(clock);
        }));
        using var client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost:7100") });

        using var healthy = await client.GetAsync("/health/ready");
        Assert.That(healthy.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        foreach (var instant in new[] { initial.AddDays(2).AddMinutes(-5), initial.AddDays(3), initial.AddDays(-2) })
        {
            clock.Current = instant;
            using var unhealthy = await client.GetAsync("/health/ready");
            Assert.That(unhealthy.StatusCode, Is.EqualTo(HttpStatusCode.ServiceUnavailable), $"Signing clock: {instant:O}");
        }
    }
}
