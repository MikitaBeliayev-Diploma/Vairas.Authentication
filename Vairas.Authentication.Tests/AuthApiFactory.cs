using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using NUnit.Framework;
using Testcontainers.PostgreSql;
using Vairas.Authentication.Business;
using Vairas.Authentication.Domain;
using Vairas.Authentication.Persistance;
using Vairas.Authentication.Security;

namespace Vairas.Authentication.Tests;

public sealed class AuthApiFactory(Dictionary<string, string?> config, FakeOidcHandler oidc) : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseContentRoot(Path.Combine(TestEnvironment.Root, "Vairas.Authentication"));
        builder.ConfigureAppConfiguration((_, c) => c.AddInMemoryCollection(config));
        builder.ConfigureLogging(l => l.ClearProviders());
        builder.ConfigureTestServices(s => s.AddHttpClient("oidc").ConfigurePrimaryHttpMessageHandler(() => oidc));
    }
}
