using Microsoft.EntityFrameworkCore.Migrations;

namespace Vairas.Authentication.Persistance.Migrations;

public partial class RecordRevocationOutcomes : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        ALTER TABLE auth_operation DROP CONSTRAINT auth_operation_target_session_id_identity_id_fkey;
        ALTER TABLE auth_operation ADD COLUMN outcome_status integer NOT NULL DEFAULT 200 CHECK (outcome_status IN (200,404));
        ALTER TABLE auth_operation ALTER COLUMN outcome_status DROP DEFAULT;
        """);

    // Rejected targets need not exist or belong to the caller. PostgreSQL refuses this rollback if such
    // retained records cannot satisfy the old FK; no audit history is silently deleted to make it succeed.
    protected override void Down(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        ALTER TABLE auth_operation ADD CONSTRAINT auth_operation_target_session_id_identity_id_fkey
          FOREIGN KEY(target_session_id,identity_id) REFERENCES auth_session(session_id,identity_id);
        ALTER TABLE auth_operation DROP COLUMN outcome_status;
        """);
}
