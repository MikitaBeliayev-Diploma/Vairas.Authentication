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

public sealed class TestEnvironment(Dictionary<string, string?>? overrides = null) : IAsyncDisposable
{
    private PostgreSqlContainer? container;
    private string admin = "";
    private string database = "";
    private string ownerRole = "";
    private string runtimeRole = "";
    private readonly List<string> siblingDatabases = [];
    public string OwnerConnection { get; private set; } = "";
    public string RuntimeConnection { get; private set; } = "";
    public string Temp { get; } = Path.Combine(Path.GetTempPath(), "vairas-auth-tests-" + Guid.NewGuid().ToString("N"));
    public AuthApiFactory Factory { get; private set; } = null!;
    public HttpClient Client { get; private set; } = null!;
    public FakeOidcHandler Oidc { get; } = new();
    public const string Password = "Valid passphrase 2026";
    public string WorkloadSecret { get; } = AuthPolicy.RandomSecret();
    public static AuditContext Audit() => new(Guid.NewGuid());

    public async Task StartAsync()
    {
        admin = Environment.GetEnvironmentVariable("VAIRAS_TEST_ADMIN_CONNECTION") ?? "";
        if (admin.Length == 0)
        {
            container = new PostgreSqlBuilder("postgres:17").WithPassword(AuthPolicy.RandomSecret()).Build();
            await container.StartAsync();
            admin = container.GetConnectionString();
        }
        var suffix = Guid.NewGuid().ToString("N");
        database = "auth_test_" + suffix;
        ownerRole = "auth_owner_" + suffix;
        runtimeRole = "auth_runtime_" + suffix;
        var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        await SqlAsync(admin, $"CREATE ROLE {ownerRole} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS; CREATE ROLE {runtimeRole} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;");
        await SqlAsync(admin, $"CREATE DATABASE {database} OWNER {ownerRole}");
        OwnerConnection = new NpgsqlConnectionStringBuilder(admin) { Database = database, Username = ownerRole, Password = password }.ConnectionString;
        RuntimeConnection = new NpgsqlConnectionStringBuilder(admin) { Database = database, Username = runtimeRole, Password = password }.ConnectionString;
        var prepare = await File.ReadAllTextAsync(Path.Combine(Root, "database", "prepare-schema.sql"));
        await SqlAsync(new NpgsqlConnectionStringBuilder(admin) { Database = database }.ConnectionString,
            prepare.Replace("v_authentication_migration", ownerRole));
        await using (var db = OwnerDb()) await db.Database.MigrateAsync();
        var grants = await File.ReadAllTextAsync(Path.Combine(Root, "database", "runtime-grants.sql"));
        await SqlAsync(OwnerConnection, grants.Replace("v_authentication_runtime", runtimeRole).Replace("v_authentication_migration", ownerRole));
        Directory.CreateDirectory(Temp);
        var certificatePath = Path.Combine(Temp, "signing.pfx");
        using (var rsa = RSA.Create(2048))
        {
            var request = new CertificateRequest("CN=Vairas-Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(2));
            await File.WriteAllBytesAsync(certificatePath, certificate.Export(X509ContentType.Pfx, "test-only"));
        }
        using var hasher = new PasswordHasher();
        var config = new Dictionary<string, string?>
        {
            ["ConnectionStrings:Authentication"] = RuntimeConnection,
            ["Authentication:SigningCertificatePath"] = certificatePath,
            ["Authentication:SigningCertificatePassword"] = "test-only",
            ["Authentication:WorkloadClients:user-management:SecretHash"] = hasher.Hash(WorkloadSecret),
            ["Authentication:WorkloadClients:user-management:Scopes:0"] = "identity.validate",
            ["Authentication:WorkloadClients:user-management:Scopes:1"] = "school.profile-provisioning",
            ["Authentication:WorkloadClients:user-management:Scopes:2"] = "confirmations.validate",
            ["Authentication:WorkloadClients:reader:SecretHash"] = hasher.Hash(WorkloadSecret),
            ["Authentication:WorkloadClients:reader:Scopes:0"] = "profiles.status.read",
            ["Authentication:BrowserOrigins:0"] = "https://frontend.test",
            ["Authentication:OidcProviders:test:Issuer"] = "https://issuer.test",
            ["Authentication:OidcProviders:test:ClientId"] = "test-client",
            ["Authentication:OidcProviders:test:ClientSecret"] = "test-client-secret",
            ["Authentication:OidcProviders:test:RedirectUris:0"] = "https://frontend.test/oidc/callback",
            ["Protection:KeyRingPath"] = Path.Combine(Temp, "keys"),
            ["Protection:CertificatePath"] = certificatePath,
            ["Protection:CertificatePassword"] = "test-only",
            ["Smtp:Sender"] = "auth@example.test",
            ["Smtp:ChallengePage"] = "https://frontend.test/auth/challenge",
            ["Smtp:WorkerEnabled"] = "false",
            ["RateLimits:RequestsPerMinute"] = "10000"
        };
        if (overrides is not null) foreach (var pair in overrides) config[pair.Key] = pair.Value;
        Factory = new(config, Oidc);
        Client = Factory.CreateClient(new() { BaseAddress = new Uri("https://localhost:7100"), HandleCookies = false });
    }
    public static string Root => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../.."));
    public AuthDbContext OwnerDb() => new(new DbContextOptionsBuilder<AuthDbContext>().UseNpgsql(OwnerConnection).Options);
    public async Task<T> Call<T>(Func<IAuthenticationService, Task<T>> action)
    {
        using var scope = Factory.Services.CreateScope();
        return await action(scope.ServiceProvider.GetRequiredService<IAuthenticationService>());
    }
    public async Task<ChallengeMail> MailAsync(string email, string purpose = "VerifyEmail")
    {
        await using var db = OwnerDb();
        var row = await (from c in db.Set<AccountChallenge>() join d in db.Set<ChallengeDelivery>() on c.ChallengeId equals d.ChallengeId
                         where c.LoginEmail == email && c.Purpose == purpose && c.InvalidatedAt == null && c.ConsumedAt == null
                         select d).SingleAsync();
        return JsonSerializer.Deserialize<ChallengeMail>(Factory.Services.GetRequiredService<ISecretProtector>().Unprotect("mail", row.ProtectedPayload!))!;
    }
    public async Task<(string Email, TokenPair Pair)> UserAsync()
    {
        var email = Guid.NewGuid().ToString("N") + "@example.test";
        await Call(s => s.RegisterAsync(new(email, Password), Audit(), default));
        var mail = await MailAsync(email);
        await Call(s => s.CompleteAsync(new(mail.Token, null), Audit(), default));
        return (email, await Call(s => s.LoginAsync(new(email, Password), Audit(), default)));
    }
    public async Task<string> WorkloadTokenAsync(string client = "user-management", string scope = "identity.validate")
    {
        using var response = await Client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        { ["grant_type"] = "client_credentials", ["client_id"] = client, ["client_secret"] = WorkloadSecret, ["scope"] = scope }));
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
        return (await response.Content.ReadFromJsonAsync<WorkloadTokenResponse>())!.AccessToken;
    }
    public static async Task SqlAsync(string connection, string sql)
    {
        await using var db = new NpgsqlConnection(connection); await db.OpenAsync();
        await using var command = new NpgsqlCommand(sql, db); await command.ExecuteNonQueryAsync();
    }
    public async Task<(string Owner, string Runtime)> CreateSiblingDatabaseAsync()
    {
        var name = "um_test_" + Guid.NewGuid().ToString("N");
        await SqlAsync(admin, $"CREATE DATABASE {name} OWNER {ownerRole}");
        siblingDatabases.Add(name);
        return (new NpgsqlConnectionStringBuilder(OwnerConnection) { Database = name }.ConnectionString,
            new NpgsqlConnectionStringBuilder(RuntimeConnection) { Database = name }.ConnectionString);
    }
    public async Task PrepareSiblingDatabaseAsync(string ownerConnection)
    {
        var prepare = await File.ReadAllTextAsync(Path.Combine(Root, "../Vairas.UserManagement/database/prepare-schema.sql"));
        var databaseName = new NpgsqlConnectionStringBuilder(ownerConnection).Database;
        await SqlAsync(new NpgsqlConnectionStringBuilder(admin) { Database = databaseName }.ConnectionString,
            prepare.Replace("v_user_management_migration", ownerRole));
    }
    public async Task GrantSiblingRuntimeAsync(string ownerConnection)
    {
        var grants = await File.ReadAllTextAsync(Path.Combine(Root, "../Vairas.UserManagement/database/database-roles.sql"));
        await SqlAsync(ownerConnection, grants.Replace("v_user_management_runtime", runtimeRole).Replace("v_user_management_migration", ownerRole));
    }
    public Task GrantRuntimeOwnerMembershipAsync() => SqlAsync(admin, $"GRANT {ownerRole} TO {runtimeRole}");
    public async ValueTask DisposeAsync()
    {
        Client?.Dispose();
        if (Factory is not null) await Factory.DisposeAsync();
        Oidc.Dispose();
        NpgsqlConnection.ClearAllPools();
        if (admin.Length != 0 && database.Length != 0)
        {
            foreach (var sibling in siblingDatabases) await SqlAsync(admin, $"DROP DATABASE IF EXISTS {sibling} WITH (FORCE)");
            await SqlAsync(admin, $"DROP DATABASE IF EXISTS {database} WITH (FORCE)");
            await SqlAsync(admin, $"DROP ROLE IF EXISTS {runtimeRole}; DROP ROLE IF EXISTS {ownerRole};");
        }
        if (container is not null) await container.DisposeAsync();
        // Certificate/key files are synthetic test artifacts retained in the reported temp directory.
    }
}
