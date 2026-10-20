-- Application roles. serk_app holds privileges (granted by migration 0001);
-- serk_api is the login role the API uses. It is neither superuser nor table
-- owner, so row-level security is enforced on every query.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_app') THEN
    CREATE ROLE serk_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_api') THEN
    CREATE ROLE serk_api LOGIN PASSWORD 'serk_api' IN ROLE serk_app;  -- change the password in production
  END IF;
END$$;
