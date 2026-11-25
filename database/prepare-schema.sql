-- Run as database administrator against the new Authentication database, before EF migrations.
-- Database ownership alone does not transfer public schema ownership on PostgreSQL 14.
ALTER SCHEMA public OWNER TO v_authentication_migration;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE,CREATE ON SCHEMA public TO v_authentication_migration;
