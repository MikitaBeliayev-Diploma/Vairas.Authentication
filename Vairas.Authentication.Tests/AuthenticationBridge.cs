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

public sealed class AuthenticationBridge(HttpClient client) : HttpMessageHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        // Both applications execute their real HTTP pipelines; this bridge replaces only the network transport.
        if (request.RequestUri!.Host != "localhost" || request.RequestUri.Port != 7100) throw new HttpRequestException("Unexpected integration target.");
        using var forwarded = new HttpRequestMessage(request.Method, request.RequestUri);
        foreach (var header in request.Headers) forwarded.Headers.TryAddWithoutValidation(header.Key, header.Value);
        if (request.Content is not null)
        {
            forwarded.Content = new ByteArrayContent(await request.Content.ReadAsByteArrayAsync(ct));
            foreach (var header in request.Content.Headers) forwarded.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        return await client.SendAsync(forwarded, ct);
    }
}
