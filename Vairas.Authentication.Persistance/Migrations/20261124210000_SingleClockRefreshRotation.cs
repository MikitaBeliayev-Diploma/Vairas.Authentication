using Microsoft.EntityFrameworkCore.Migrations;

namespace Vairas.Authentication.Persistance.Migrations;

/// <summary>
/// Refresh rotation previously stamped consumption/successor/revocation times with the database clock while every other
/// session and token time came from the application's TimeProvider. A host clock ahead of PostgreSQL made an immediate
/// refresh violate ck_refresh_token_4 (consumed_at &gt;= created_at), and a database clock ahead of the host made a later
/// application-side revocation violate ck_refresh_token_5. Rotation now takes the application time and never stamps a
/// fact earlier than the family facts it follows, so the existing temporal constraints hold under bounded skew.
/// </summary>
public partial class SingleClockRefreshRotation : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        DROP FUNCTION auth_rotate_refresh(text,uuid,text,uuid);
        CREATE FUNCTION auth_rotate_refresh(p_old_digest text,p_new_id uuid,p_new_digest text,p_correlation uuid,p_at timestamptz)
        RETURNS TABLE(outcome text,identity_id uuid,session_id uuid) LANGUAGE plpgsql AS $$
        DECLARE t refresh_token; s auth_session; a identity; at_time timestamptz;
        BEGIN
         IF p_at IS NULL THEN RAISE EXCEPTION 'Rotation time is required'; END IF;
         SELECT * INTO t FROM refresh_token r WHERE r.secret_digest=p_old_digest;
         IF NOT FOUND THEN RETURN QUERY SELECT 'Denied'::text,NULL::uuid,NULL::uuid; RETURN; END IF;
         SELECT * INTO s FROM auth_session x WHERE x.session_id=t.session_id;
         SELECT * INTO a FROM identity x WHERE x.identity_id=s.identity_id FOR UPDATE;
         SELECT * INTO s FROM auth_session x WHERE x.session_id=t.session_id FOR UPDATE;
         SELECT * INTO t FROM refresh_token r WHERE r.refresh_token_id=t.refresh_token_id FOR UPDATE;
         -- Application time, clamped so no new fact precedes the session or any token already in its family.
         SELECT GREATEST(p_at,s.created_at,max(r.created_at)) INTO at_time FROM refresh_token r WHERE r.session_id=s.session_id;
         IF t.consumed_at IS NOT NULL THEN
          UPDATE auth_session x SET revoked_at=COALESCE(x.revoked_at,at_time),
            revocation_reason=COALESCE(x.revocation_reason,'RefreshReuse') WHERE x.session_id=s.session_id;
          UPDATE refresh_token r SET revoked_at=COALESCE(r.revoked_at,at_time) WHERE r.session_id=s.session_id;
          INSERT INTO security_event VALUES(p_new_id,a.identity_id,s.session_id,'RefreshReuse','Denied',p_correlation,at_time);
          RETURN QUERY SELECT 'Denied'::text,NULL::uuid,NULL::uuid; RETURN;
         END IF;
         IF a.security_state<>'Enabled' OR s.revoked_at IS NOT NULL OR s.expires_at<=at_time
            OR t.expires_at<=at_time OR t.revoked_at IS NOT NULL THEN
          RETURN QUERY SELECT 'Denied'::text,NULL::uuid,NULL::uuid; RETURN;
         END IF;
         UPDATE refresh_token r SET consumed_at=at_time WHERE r.refresh_token_id=t.refresh_token_id;
         INSERT INTO refresh_token(refresh_token_id,session_id,parent_token_id,secret_digest,created_at,expires_at)
         VALUES(p_new_id,s.session_id,t.refresh_token_id,p_new_digest,at_time,LEAST(at_time+interval '7 days',s.expires_at));
         INSERT INTO security_event VALUES(p_new_id,a.identity_id,s.session_id,'RefreshRotated','Succeeded',p_correlation,at_time);
         RETURN QUERY SELECT 'Rotated'::text,a.identity_id,s.session_id;
        END $$;
        ALTER FUNCTION auth_rotate_refresh(text,uuid,text,uuid,timestamptz) SET search_path=pg_catalog,public,pg_temp;
        REVOKE ALL ON FUNCTION auth_rotate_refresh(text,uuid,text,uuid,timestamptz) FROM PUBLIC;
        """);

    // Restores the original database-clock function; runtime-grants.sql must then be re-applied for its signature.
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("DROP FUNCTION auth_rotate_refresh(text,uuid,text,uuid,timestamptz);");
        var initial = InitialAuthentication.Read("Initial.sql");
        var start = initial.IndexOf("CREATE FUNCTION auth_rotate_refresh", StringComparison.Ordinal);
        var end = initial.IndexOf("REVOKE ALL ON FUNCTION auth_rotate_refresh", StringComparison.Ordinal);
        var revoke = initial.IndexOf('\n', end);
        migrationBuilder.Sql(initial[start..(revoke < 0 ? initial.Length : revoke)]);
    }
}
