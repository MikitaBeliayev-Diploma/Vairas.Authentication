using System.Net;
using Npgsql;
using NUnit.Framework;

namespace Vairas.Authentication.Tests;

[TestFixture, Category("Integration")]
public sealed class DatabasePermissionsTests
{
    [Test]
    public async Task ProvisionedRuntimeHasNoSchemaDatabaseCreateTemporaryOrOwnershipPrivileges()
    {
        await using var environment = new TestEnvironment();
        await environment.StartAsync();
        await using var connection = new NpgsqlConnection(environment.RuntimeConnection);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("""
            SELECT has_schema_privilege('public','CREATE'),
                   has_database_privilege(current_database(),'CREATE'),
                   has_database_privilege(current_database(),'TEMP'),
                   EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public'
                           AND pg_has_role(current_user,tableowner,'MEMBER'))
            """, connection);
        await using var reader = await command.ExecuteReaderAsync();
        Assert.That(await reader.ReadAsync(), Is.True);
        for (var index = 0; index < 4; index++) Assert.That(reader.GetBoolean(index), Is.False, $"Privilege {index}");
        using var readiness = await environment.Client.GetAsync("/health/ready");
        Assert.That(readiness.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [TestCase("schema-direct")]
    [TestCase("schema-public")]
    [TestCase("database-create")]
    [TestCase("temporary")]
    [TestCase("owner-membership")]
    public async Task ReadinessRejectsEffectiveExcessPrivileges(string privilege)
    {
        await using var environment = new TestEnvironment();
        await environment.StartAsync();
        var runtime = new NpgsqlConnectionStringBuilder(environment.RuntimeConnection).Username!;
        var database = new NpgsqlConnectionStringBuilder(environment.OwnerConnection).Database!;
        var grant = privilege switch
        {
            "schema-direct" => $"GRANT CREATE ON SCHEMA public TO {runtime}",
            "schema-public" => "GRANT CREATE ON SCHEMA public TO PUBLIC",
            "database-create" => $"GRANT CREATE ON DATABASE {database} TO {runtime}",
            "temporary" => $"GRANT TEMP ON DATABASE {database} TO {runtime}",
            _ => ""
        };
        if (privilege == "owner-membership") await environment.GrantRuntimeOwnerMembershipAsync();
        else await TestEnvironment.SqlAsync(environment.OwnerConnection, grant);
        using var readiness = await environment.Client.GetAsync("/health/ready");
        Assert.That(readiness.StatusCode, Is.EqualTo(HttpStatusCode.ServiceUnavailable));
    }

    [Test]
    public async Task GrantsFailClearlyWhenAdministratorSchemaPreparationWasOmitted()
    {
        await using var environment = new TestEnvironment();
        await environment.StartAsync();
        var sibling = await environment.CreateSiblingDatabaseAsync();
        var runtime = new NpgsqlConnectionStringBuilder(environment.RuntimeConnection).Username!;
        var owner = new NpgsqlConnectionStringBuilder(environment.OwnerConnection).Username!;
        var grants = (await File.ReadAllTextAsync(Path.Combine(TestEnvironment.Root, "database", "runtime-grants.sql")))
            .Replace("v_authentication_runtime", runtime).Replace("v_authentication_migration", owner);

        var error = Assert.ThrowsAsync<PostgresException>(() => TestEnvironment.SqlAsync(sibling.Owner, grants));

        Assert.That(error!.SqlState, Is.EqualTo("P0001"));
        Assert.That(error.MessageText, Does.Contain("prepare-schema.sql"));
    }
}
