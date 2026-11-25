using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Vairas.Authentication.Business;
using Vairas.Authentication.Persistance;
using Vairas.Authentication.Security;

namespace Vairas.Authentication.HealthChecks;

public sealed class DatabaseReadiness(AuthDbContext db, SigningKeys keys, ISecretProtector protection) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default)
    {
        try
        {
            if (!keys.CanIssueTokens) return HealthCheckResult.Unhealthy("Authentication resources unavailable.");
            var restricted = await db.Database.SqlQueryRaw<bool>("""
                SELECT (NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreatedb AND NOT r.rolcreaterole
                  AND NOT has_schema_privilege('public','CREATE')
                  AND NOT has_database_privilege(current_database(),'CREATE')
                  AND NOT has_database_privilege(current_database(),'TEMP')
                  AND NOT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public'
                                  AND pg_has_role(current_user,tableowner,'MEMBER'))) AS "Value"
                FROM pg_roles r WHERE r.rolname=current_user
                """).SingleAsync(ct);
            if (!restricted) return HealthCheckResult.Unhealthy("Authentication resources unavailable.");
            var count = await db.Database.SqlQueryRaw<int>("SELECT count(*)::integer AS \"Value\" FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('identity','password_credential','external_identity','auth_session','refresh_token','account_challenge','oidc_request','security_event','auth_operation','challenge_delivery')").SingleAsync(ct);
            var probe = AuthPolicy.RandomSecret();
            if (count != 10 || keys.ValidationKeys.Count == 0 || protection.Unprotect("health", protection.Protect("health", probe)) != probe) return HealthCheckResult.Unhealthy("Authentication resources unavailable.");
            return HealthCheckResult.Healthy();
        }
        catch (Exception) { return HealthCheckResult.Unhealthy("Authentication resources unavailable."); }
    }
}
