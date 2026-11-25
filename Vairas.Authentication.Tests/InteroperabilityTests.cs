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

[TestFixture, NonParallelizable]
public sealed class InteroperabilityTests
{
    [Test]
    public async Task RealUserManagementAcceptsNewIssuerAndRejectsSessionAfterLogout()
    {
        await using var env = new TestEnvironment();
        await env.StartAsync();
        var connections = await env.CreateSiblingDatabaseAsync();
        await env.PrepareSiblingDatabaseAsync(connections.Owner);
        var options = new DbContextOptionsBuilder<VairasDbContext>(); options.UseVairasPostgres(connections.Owner);
        await using (var db = new VairasDbContext(options.Options)) await db.Database.MigrateAsync();
        await env.GrantSiblingRuntimeAsync(connections.Owner);
        await using var factory = new UserManagementFactory(connections.Runtime, env.Client, env.WorkloadSecret);
        using var client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost:5151") });
        var (_, pair) = await env.UserAsync();
        client.DefaultRequestHeaders.Authorization = new("Bearer", pair.AccessToken);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/users/me")
        {
            Content = JsonContent.Create(new { firstName = "Synthetic", lastName = "Learner", emailAddress = (string?)null, phoneNumber = (string?)null })
        };
        request.Headers.Add("Idempotency-Key", Guid.NewGuid().ToString("D"));
        using var created = await client.SendAsync(request);
        Assert.That(created.StatusCode, Is.EqualTo(HttpStatusCode.Created), await created.Content.ReadAsStringAsync());
        using var read = await client.GetAsync("/api/v1/users/me");
        Assert.That(read.StatusCode, Is.EqualTo(HttpStatusCode.OK), await read.Content.ReadAsStringAsync());
        await env.Call(s => s.RevokeAsync(new UserActor(pair.IdentityId, pair.SessionId), pair.SessionId, Guid.NewGuid(), TestEnvironment.Audit(), default));
        using var after = await client.GetAsync("/api/v1/users/me");
        Assert.That(after.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized), await after.Content.ReadAsStringAsync());
    }
}
