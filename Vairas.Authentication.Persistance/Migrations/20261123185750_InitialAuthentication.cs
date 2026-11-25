using Microsoft.EntityFrameworkCore.Migrations;

namespace Vairas.Authentication.Persistance.Migrations;

public partial class InitialAuthentication : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(Read("Initial.sql"));

        migrationBuilder.CreateTable(
            name: "auth_operation",
            columns: table => new
            {
                operation_id = table.Column<Guid>(type: "uuid", nullable: false),
                identity_id = table.Column<Guid>(type: "uuid", nullable: false),
                source_session_id = table.Column<Guid>(type: "uuid", nullable: false),
                target_session_id = table.Column<Guid>(type: "uuid", nullable: false),
                fingerprint = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                recorded_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("auth_operation_pkey", x => x.operation_id);
                table.CheckConstraint("auth_operation_fingerprint_check", "fingerprint ~ '^[0-9a-f]{64}$'");
                table.ForeignKey(
                    name: "auth_operation_source_session_id_identity_id_fkey",
                    columns: x => new { x.source_session_id, x.identity_id },
                    principalTable: "auth_session",
                    principalColumns: new[] { "session_id", "identity_id" });
                table.ForeignKey(
                    name: "auth_operation_target_session_id_identity_id_fkey",
                    columns: x => new { x.target_session_id, x.identity_id },
                    principalTable: "auth_session",
                    principalColumns: new[] { "session_id", "identity_id" });
            });

        migrationBuilder.CreateTable(
            name: "challenge_delivery",
            columns: table => new
            {
                delivery_id = table.Column<Guid>(type: "uuid", nullable: false),
                challenge_id = table.Column<Guid>(type: "uuid", nullable: false),
                protected_payload = table.Column<string>(type: "text", nullable: true),
                status = table.Column<string>(type: "varchar(16)", maxLength: 16, nullable: false),
                attempts = table.Column<int>(type: "integer", nullable: false),
                created_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: false),
                expires_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: false),
                next_attempt_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: false),
                lease_id = table.Column<Guid>(type: "uuid", nullable: true),
                leased_until = table.Column<DateTimeOffset>(type: "timestamptz", nullable: true),
                last_error_code = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("challenge_delivery_pkey", x => x.delivery_id);
                table.UniqueConstraint("challenge_delivery_challenge_id_key", x => x.challenge_id);
                table.CheckConstraint("challenge_delivery_status_check", "status IN ('Pending','Sending','Sent','Failed','Unknown','Superseded','Expired')");
                table.CheckConstraint("challenge_delivery_attempts_check", "attempts >= 0");
                table.CheckConstraint("challenge_delivery_check", "expires_at > created_at");
                table.CheckConstraint("challenge_delivery_check1", "(lease_id IS NULL) = (leased_until IS NULL)");
                table.CheckConstraint("challenge_delivery_check2", "(status = 'Sending') = (lease_id IS NOT NULL)");
                table.CheckConstraint("challenge_delivery_check3", "status NOT IN ('Pending','Sending') OR protected_payload IS NOT NULL");
                table.ForeignKey(
                    name: "challenge_delivery_challenge_id_fkey",
                    column: x => x.challenge_id,
                    principalTable: "account_challenge",
                    principalColumn: "challenge_id");
            });

        migrationBuilder.CreateIndex(
            name: "ix_delivery_pending",
            table: "challenge_delivery",
            column: "next_attempt_at",
            filter: "status = 'Pending'");
    }
    internal static string Read(string name)
    {
        var assembly = typeof(InitialAuthentication).Assembly;
        using var stream = assembly.GetManifestResourceStream(assembly.GetManifestResourceNames().Single(n => n.EndsWith(".Sql." + name, StringComparison.Ordinal)))!;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
    protected override void Down(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        DROP FUNCTION auth_rotate_refresh(text,uuid,text,uuid);
        DROP TABLE challenge_delivery,auth_operation,security_event,oidc_request,account_challenge,refresh_token,auth_session,external_identity,password_credential,identity;
        DROP FUNCTION auth_refresh_bounds();
        """);
}
