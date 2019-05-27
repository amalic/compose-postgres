
-- ================================================================================================
-- Create function for custom schema creation
-- ================================================================================================

-- DROP FUNCTION public.create_schema(text, text, text);
CREATE OR REPLACE FUNCTION public.create_schema(IN v_svcname text, IN v_dbname text, IN v_schema text, OUT resultMessage text)
    RETURNS text
    LANGUAGE 'plpgsql'
    SECURITY DEFINER
AS $BODY$
DECLARE
    strConnectDbTarget TEXT;
    serviceRoleAdmin TEXT;
    serviceRoleUser TEXT;
    serviceRoleRead TEXT;
BEGIN
    strConnectDbTarget := 'host=localhost user=postgres dbname=' || v_dbname;

    serviceRoleAdmin := v_svcname || '_admin';
    serviceRoleUser := v_svcname || '_user';
    serviceRoleRead := v_svcname || '_read';

    PERFORM dblink_exec(strConnectDbTarget,'CREATE SCHEMA ' || v_schema || ' AUTHORIZATION ' || serviceRoleAdmin);

    PERFORM dblink_exec(strConnectDbTarget,'GRANT ALL ON SCHEMA ' || v_schema || ' TO ' || serviceRoleAdmin);
    PERFORM dblink_exec(strConnectDbTarget,'GRANT ALL ON SCHEMA ' || v_schema || ' TO ' || serviceRoleUser);
    PERFORM dblink_exec(strConnectDbTarget,'GRANT ALL ON SCHEMA ' || v_schema || ' TO ' || serviceRoleRead);

    PERFORM dblink_exec(strConnectDbTarget,
        'COMMENT ON SCHEMA ' || v_schema
            || ' IS ' || quote_literal('Primary Schema for service ' || quote_ident(v_svcname)));

    -- set grants for roles (users) and schema
    PERFORM dblink_exec(strConnectDbTarget,
        'GRANT USAGE ON SCHEMA ' || v_schema || ' TO ' || serviceRoleAdmin);

    PERFORM dblink_exec(strConnectDbTarget,
        'GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA ' || v_schema || ' TO ' || serviceRoleAdmin);

    PERFORM dblink_exec(strConnectDbTarget,
        'GRANT USAGE ON SCHEMA ' || v_schema || ' TO ' || serviceRoleUser);

    -- prepare the DDL (admin) role for grant inheritance for the DML (user) role and ready-only role.
    PERFORM dblink_exec(strConnectDbTarget,
        'ALTER DEFAULT PRIVILEGES FOR USER ' || serviceRoleAdmin || ' IN SCHEMA ' || v_schema
            || ' GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ' || serviceRoleUser);

    PERFORM dblink_exec(strConnectDbTarget,
        'ALTER DEFAULT PRIVILEGES FOR USER ' || serviceRoleAdmin || ' IN SCHEMA ' || v_schema
            || ' GRANT USAGE, SELECT ON SEQUENCES TO ' || serviceRoleUser);

    PERFORM dblink_exec(strConnectDbTarget,
        'ALTER DEFAULT PRIVILEGES FOR USER ' || serviceRoleAdmin || ' IN SCHEMA ' || v_schema
            || '  GRANT SELECT ON TABLES TO ' || serviceRoleRead);

    PERFORM dblink_exec(strConnectDbTarget,
        'ALTER DEFAULT PRIVILEGES FOR USER ' || serviceRoleAdmin || ' IN SCHEMA ' || v_schema
            || '  GRANT USAGE, SELECT ON SEQUENCES TO ' || serviceRoleRead);

    resultMessage := 'OK: Schema ' || quote_literal(v_schema) || ' created in database ' || quote_literal(v_dbname);
END;
$BODY$
    -- Set a secure search_path: trusted schema(s), then 'pg_temp'.
    SET search_path = public, pg_temp;

ALTER FUNCTION public.create_schema(text, text, text)
    OWNER TO postgres;

-- =================================================================================================
-- Handle execution rights on the create functions
-- =================================================================================================

REVOKE EXECUTE ON FUNCTION create_schema(text, text, text) FROM public;
GRANT EXECUTE ON FUNCTION create_schema(text, text, text) TO database_creator;
