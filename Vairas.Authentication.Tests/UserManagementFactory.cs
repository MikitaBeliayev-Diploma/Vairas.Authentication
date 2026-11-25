extern alias UserManagement;

using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using NUnit.Framework;
using Vairas.Authentication.Business;
using Vairas.UserManagement.Persistance.DataAccess;
using DependencyOptions = UserManagement::Vairas.UserManagement.Configuration.Options.DependencyOptions;
using OutboxOptions = UserManagement::Vairas.UserManagement.Configuration.Options.OutboxOptions;
using UserManagementProgram = UserManagement::Program;

namespace Vairas.Authentication.Tests;

public sealed class UserManagementFactory(string connection, HttpClient authentication, string secret) : WebApplicationFactory<UserManagementProgram>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseContentRoot(Path.GetFullPath(Path.Combine(TestEnvironment.Root, "../Vairas.UserManagement/Vairas.UserManagement")));
        builder.ConfigureLogging(l => l.ClearProviders());
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<DbContextOptions<VairasDbContext>>();
            services.RemoveAll<Microsoft.EntityFrameworkCore.Infrastructure.IDbContextOptionsConfiguration<VairasDbContext>>();
            services.AddDbContext<VairasDbContext>(o => o.UseVairasPostgres(connection));
            services.Configure<DependencyOptions>(o =>
            {
                o.AuthBaseUrl = "https://localhost:7100/"; o.TokenEndpoint = "https://localhost:7100/connect/token";
                o.ClientId = "user-management"; o.ClientSecret = secret;
            });
            services.Configure<OutboxOptions>(o => o.Enabled = false);
            services.AddHttpClient("dependencies").ConfigurePrimaryHttpMessageHandler(() => new AuthenticationBridge(authentication));
            foreach (var scheme in new[] { "User", "Workload" })
                services.PostConfigure<JwtBearerOptions>(scheme, o =>
                {
                    o.Authority = "https://localhost:7100"; o.RequireHttpsMetadata = true;
                    o.MetadataAddress = "https://localhost:7100/.well-known/openid-configuration";
                    o.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(o.MetadataAddress,
                        new OpenIdConnectConfigurationRetriever(), new HttpDocumentRetriever(authentication) { RequireHttps = true });
                });
        });
    }
}
