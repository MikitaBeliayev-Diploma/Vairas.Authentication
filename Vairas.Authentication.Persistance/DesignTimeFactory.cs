using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Vairas.Authentication.Persistance;

public sealed class DesignTimeFactory : IDesignTimeDbContextFactory<AuthDbContext>
{
    public AuthDbContext CreateDbContext(string[] args)
    {
        var connection = Environment.GetEnvironmentVariable("VAIRAS_MIGRATION_CONNECTION") ??
            "Host=localhost;Database=vairas_authentication;Username=v_authentication_migration";
        return new(new DbContextOptionsBuilder<AuthDbContext>().UseNpgsql(connection).Options);
    }
}
