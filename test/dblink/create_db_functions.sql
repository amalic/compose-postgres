-- reqs: securely create new databases on behalf of superuser without exposing it's credentials
-- idea: provide a function encapsulating create_db for a dedicated role != postgres/superadmin
-- todo: the CREATE DATABASE statement cannot be used in a tx context, but the function defines one,
--       therefore the statements needs to be decoupled from the tx context.
--       the dblink extension for postgresql is a way to realize this.
-- mind the hints for safe declaration: https://www.postgresql.org/docs/9.6/sql-createfunction.html

-- =================================================================================================
-- Activate and review Dblink extension
-- =================================================================================================

-- review version to determine todo concerning dblink (built-in or not)
SELECT * FROM pg_settings WHERE name IN ('server_version', 'server_version_num');

-- create dblink extension if not pre-installed
CREATE EXTENSION dblink;

-- verify availability of the extension in the current schema (e.g. schema public in db postgres)
SELECT pg_namespace.nspname, pg_proc.proname
    FROM pg_proc, pg_namespace
    WHERE pg_proc.pronamespace=pg_namespace.oid AND pg_proc.proname LIKE '%dblink%';

-- check dblink connect to localhost
SELECT dblink_connect('host=localhost user=postgres dbname=postgres');


-- =================================================================================================
-- Create user for service database creation
-- =================================================================================================

-- Create a new role with the right to LOGIN and CREATEDB without being superuser.
CREATE USER database_creator WITH LOGIN NOSUPERUSER NOINHERIT CREATEDB CREATEROLE NOREPLICATION;

-- Allow it to connect to postgres database:
GRANT CONNECT ON DATABASE postgres TO database_creator;
GRANT postgres TO database_creator;
ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO database_creator;
ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO database_creator;


-- ================================================================================================
-- Create function for role creation
-- ================================================================================================

-- DROP FUNCTION public.create_role(text, text, text);
CREATE OR REPLACE FUNCTION public.create_role(IN v_svcname text, IN v_role text, IN v_pghashed_password text, OUT resultMessage text)
    RETURNS text
    LANGUAGE 'plpgsql'
    SECURITY DEFINER
AS $BODY$
DECLARE
    username TEXT;
    roleGrant TEXT;
BEGIN
    username := v_svcname || '_' || v_role;
    PERFORM dblink_exec('host=localhost user=postgres dbname=postgres',
                        'CREATE ROLE ' || username
                            || ' LOGIN ENCRYPTED PASSWORD ' || quote_literal(v_pghashed_password)
                            || ' NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE NOREPLICATION');
    RAISE NOTICE 'OK: Generated role % with encrypted password %', username, v_pghashed_password;

    CASE v_role
        WHEN 'admin' THEN
            roleGrant := 'GRANT db_admin TO ' || username;
        WHEN 'user' THEN
            roleGrant := 'GRANT data_writer TO ' || username;
        ELSE
            roleGrant := 'GRANT data_reader TO ' || username;
        END CASE;

    PERFORM dblink_exec('host=localhost user=postgres dbname=postgres', roleGrant);

    resultMessage := 'OK: ' || quote_literal(roleGrant);
END;
$BODY$
    -- Set a secure search_path: trusted schema(s), then 'pg_temp'.
    SET search_path = public, pg_temp;

ALTER FUNCTION public.create_role(text, text, text)
    OWNER TO postgres;


-- ================================================================================================
-- Create function for database creation
-- ================================================================================================

-- DROP FUNCTION public.create_database(text, text);
CREATE OR REPLACE FUNCTION public.create_database(IN v_svcname text, IN v_dbname text, OUT resultMessage text)
    RETURNS text
    LANGUAGE 'plpgsql'
    SECURITY DEFINER
AS $BODY$
DECLARE
    strConnectDbPostgres TEXT;
    strConnectDbTarget TEXT;
    dbEncoding TEXT;
    dbCollation TEXT;
    dbCtype TEXT;
    dbConnectionLimit numeric;
    schemaName TEXT;
    serviceRoleAdmin TEXT;
    serviceRoleUser TEXT;
    serviceRoleRead TEXT;
BEGIN
    strConnectDbPostgres := 'host=localhost user=postgres dbname=postgres';
    strConnectDbTarget := 'host=localhost user=postgres dbname=' || v_dbname;
    dbEncoding := 'UTF-8';
    dbCollation := 'en_US.utf8';
    dbCtype := 'en_US.utf8';
    dbConnectionLimit := -1;

    -- Create a database with default constraints as defined in service conventions
    PERFORM dblink_exec(strConnectDbPostgres,
                        'CREATE DATABASE ' || v_dbname
                            || ' WITH OWNER = postgres'
                            || ' TABLESPACE = pg_default'
                            || ' ENCODING = ' || quote_literal(dbEncoding)
                            || ' LC_COLLATE = ' || quote_literal(dbCollation)
                            || ' LC_CTYPE = ' || quote_literal(dbCtype)
                            || ' CONNECTION LIMIT = ' || dbConnectionLimit);

    PERFORM dblink_exec(strConnectDbPostgres,
                        'COMMENT ON DATABASE ' || v_dbname
                            || ' IS ' || quote_literal('Database for service ' || quote_ident(v_svcname)));

    PERFORM dblink_exec(strConnectDbPostgres,
                        'GRANT CONNECT, TEMPORARY ON DATABASE ' || v_dbname || ' TO public');

    PERFORM dblink_exec(strConnectDbPostgres,
                        'GRANT ALL ON DATABASE ' || v_dbname || ' TO postgres');

    -- Connect to the newly created database and create the primary schema and grants
    schemaName := v_dbname;
    serviceRoleAdmin := v_svcname || '_admin';
    serviceRoleUser := v_svcname || '_user';
    serviceRoleRead := v_svcname || '_read';
    PERFORM dblink_exec(strConnectDbTarget,
                        'CREATE SCHEMA ' || schemaName || ' AUTHORIZATION ' || serviceRoleAdmin);

    PERFORM dblink_exec(strConnectDbTarget,'GRANT ALL ON SCHEMA ' || schemaName || ' TO ' || serviceRoleAdmin);
    PERFORM dblink_exec(strConnectDbTarget,'GRANT ALL ON SCHEMA ' || schemaName || ' TO db_admin');
    PERFORM dblink_exec(strConnectDbTarget,'GRANT ALL ON SCHEMA ' || schemaName || ' TO ' || serviceRoleUser);
    PERFORM dblink_exec(strConnectDbTarget,'GRANT ALL ON SCHEMA ' || schemaName || ' TO ' || serviceRoleRead);

    PERFORM dblink_exec(strConnectDbTarget,
                        'COMMENT ON SCHEMA ' || schemaName
                            || ' IS ' || quote_literal('Primary Schema for service ' || quote_ident(v_svcname)));

    -- set grants for roles (users) and schema
    PERFORM dblink_exec(strConnectDbTarget,
                        'GRANT ALL PRIVILEGES ON DATABASE ' || v_dbname  || ' TO ' || serviceRoleAdmin);
    PERFORM dblink_exec(strConnectDbTarget,
                        'GRANT USAGE ON SCHEMA ' || schemaName  || ' TO ' || serviceRoleAdmin);

    PERFORM dblink_exec(strConnectDbTarget,
                        'GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA ' || schemaName  || ' TO ' || serviceRoleAdmin);

    PERFORM dblink_exec(strConnectDbTarget,
                        'GRANT USAGE ON SCHEMA ' || schemaName  || ' TO ' || serviceRoleUser);

    -- prepare the DDL (admin) role for grant inheritance for the DML (user) role and ready-only role.
    PERFORM dblink_exec(strConnectDbTarget,
                        'ALTER DEFAULT PRIVILEGES FOR USER ' || serviceRoleAdmin || ' IN SCHEMA ' || schemaName
                            || ' GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ' || serviceRoleUser);

    PERFORM dblink_exec(strConnectDbTarget,
                        'ALTER DEFAULT PRIVILEGES FOR USER ' || serviceRoleAdmin || ' IN SCHEMA ' || schemaName
                            || ' GRANT USAGE, SELECT ON SEQUENCES TO ' || serviceRoleUser);

    PERFORM dblink_exec(strConnectDbTarget,
                        'ALTER DEFAULT PRIVILEGES FOR USER ' || serviceRoleAdmin || ' IN SCHEMA ' || schemaName
                            || '  GRANT SELECT ON TABLES TO ' || serviceRoleRead);

    PERFORM dblink_exec(strConnectDbTarget,
                        'ALTER DEFAULT PRIVILEGES FOR USER ' || serviceRoleAdmin || ' IN SCHEMA ' || schemaName
                            || '  GRANT USAGE, SELECT ON SEQUENCES TO ' || serviceRoleRead);

    resultMessage := 'OK: Database ' || quote_literal(v_dbname) || ' created with schema ' || quote_literal(schemaName) || ' and service role grants.';
END;
$BODY$
    -- Set a secure search_path: trusted schema(s), then 'pg_temp'.
    SET search_path = public, pg_temp;

ALTER FUNCTION public.create_database(text, text)
    OWNER TO postgres;

-- =================================================================================================
-- Handle execution rights on the create functions
-- =================================================================================================

REVOKE EXECUTE ON FUNCTION create_database(text,text) FROM public;
GRANT EXECUTE ON FUNCTION create_database(text,text) TO database_creator;

REVOKE EXECUTE ON FUNCTION create_role(text,text,text) FROM public;
GRANT EXECUTE ON FUNCTION create_role(text,text,text) TO database_creator;
